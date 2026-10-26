#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
namespace fs = std::filesystem;
static constexpr const char* scriptPath = "/usr/local/bin/challenge.sh";
static constexpr const char* keyPath = "/home/we6jbo/.ads/challenge.key";
static constexpr const char* timePath = "/tmp/fwd/challenge_time.txt";
static constexpr const char* provenance = "TG333041,TG654147";
static constexpr const char* projectRoot = "/home/we6jbo/Projects/Carventory";
static constexpr const char* backupRoot = "/home/we6jbo/.forvibe-102526";
// Required user-selected passphrase. WARNING: embedded in the source and binary.
static constexpr const char* backupPassphrase = "BfxzCyGpJWl2MrY";

std::string hex(const unsigned char* p, size_t n) {
    static constexpr char d[] = "0123456789abcdef";
    std::string result; result.reserve(n * 2);
    for (size_t i=0; i<n; ++i) { result += d[p[i] >> 4]; result += d[p[i] & 15]; }
    return result;
}
std::vector<unsigned char> unhex(const std::string& v) {
    if (v.size() != 64) throw std::runtime_error("Invalid 256-bit key length");
    std::vector<unsigned char> out;
    for(size_t i=0;i<v.size();i+=2) {
        auto digit=[](char c)->int {
            if(c>='0' && c<='9') return c-'0';
            if(c>='a' && c<='f') return c-'a'+10;
            return -1;
        };
        int a=digit(v[i]), b=digit(v[i+1]);
        if(a<0 || b<0) throw std::runtime_error("Invalid key encoding");
        out.push_back(static_cast<unsigned char>((a<<4)|b));
    }
    return out;
}
std::string readOneLine(const char* filename) {
    std::ifstream in(filename);
    if(!in) throw std::runtime_error(std::string("Cannot open ")+filename);
    std::string line;
    if(!std::getline(in,line)) throw std::runtime_error("Empty file");
    return line;
}
std::string roundUpLocalTime() {
    std::time_t now=std::time(nullptr);
    now = ((now + 299) / 300) * 300;
    std::tm result{};
    if(!localtime_r(&now,&result)) throw std::runtime_error("localtime_r failed");
    char s[64]{};
    if(!std::strftime(s,sizeof(s),"%Y-%m-%dT%H:%M:%S%z",&result)) throw std::runtime_error("strftime failed");
    return s;
}
std::string expectedResponse(const std::string& nonce,const std::string& stamp) {
    auto key=unhex(readOneLine(keyPath));
    const std::string message="challenge-v1|"+nonce+"|"+stamp;
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int count=0;
    if(!HMAC(EVP_sha256(),key.data(),static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(message.data()),
             message.size(),digest,&count)) throw std::runtime_error("HMAC failed");
    return hex(digest,count);
}
struct ScriptResult {int exitCode;std::string output;};
ScriptResult runScript(const std::string& nonce) {
    int fds[2]; if(pipe(fds)!=0) throw std::runtime_error("pipe failed");
    pid_t pid=fork();
    if(pid<0) {close(fds[0]);close(fds[1]);throw std::runtime_error("fork failed");}
    if(pid==0) {close(fds[0]);dup2(fds[1],STDOUT_FILENO);close(fds[1]);execl(scriptPath,scriptPath,nonce.c_str(),(char*)nullptr);_exit(127);}
    close(fds[1]);std::string output;char buffer[256];ssize_t n;
    while((n=read(fds[0],buffer,sizeof buffer))>0) output.append(buffer,n);
    close(fds[0]);int status=0;
    if(waitpid(pid,&status,0)<0) throw std::runtime_error("waitpid failed");
    return {WIFEXITED(status)?WEXITSTATUS(status):-1,output};
}
std::string performChallenge() {
    for(int attempt=0;attempt<10;++attempt) {
        std::array<unsigned char,16> bytes{};
        if(RAND_bytes(bytes.data(),bytes.size())!=1) throw std::runtime_error("RAND_bytes failed");
        const std::string nonce=hex(bytes.data(),bytes.size());
        const auto result=runScript(nonce);
        if(result.exitCode==3 && result.output=="DUPLICATE\n") continue;
        if(result.exitCode!=0) throw std::runtime_error("Script failed: "+result.output);
        std::istringstream in(result.output);std::string status,stamp,response,extra;
        if(!(in>>status>>stamp>>response) || (in>>extra) || status!="OK") throw std::runtime_error("Invalid script response");
        if(response!=expectedResponse(nonce,stamp)) throw std::runtime_error("Challenge response authentication failed");
        if(readOneLine(timePath)!=stamp || roundUpLocalTime()!=stamp) throw std::runtime_error("time sync does not match");
        return stamp;
    }
    throw std::runtime_error("Too many duplicate random challenges");
}
bool verify() {
    try {std::cout<<"Verified time: "<<performChallenge()<<'\n';return true;}
    catch(const std::exception& ex) {std::cerr<<"Challenge verification failed: "<<ex.what()<<'\n';return false;}
}
void logMilestone(const std::string& msg) {
    std::cerr<<"[Carventory] "<<msg<<'\n';
    pid_t pid=fork();
    if(pid==0) {execlp("logger","logger","-t","carventory",msg.c_str(),(char*)nullptr);_exit(127);}
    if(pid>0) {int status;while(waitpid(pid,&status,0)<0 && errno==EINTR) {}}
}
std::string digestMd5(const fs::path& f) {
    std::ifstream in(f,std::ios::binary);if(!in) throw std::runtime_error("Unable to open main.cpp");
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();if(!ctx) throw std::runtime_error("MD5 allocation failed");
    if(EVP_DigestInit_ex(ctx,EVP_md5(),nullptr)!=1) {EVP_MD_CTX_free(ctx);throw std::runtime_error("MD5 init failed");}
    char buf[8192];while(in) {in.read(buf,sizeof buf);if(in.gcount()>0 && EVP_DigestUpdate(ctx,buf,size_t(in.gcount()))!=1) {EVP_MD_CTX_free(ctx);throw std::runtime_error("MD5 update failed");}}
    unsigned char result[EVP_MAX_MD_SIZE];unsigned int len=0;
    if(EVP_DigestFinal_ex(ctx,result,&len)!=1){EVP_MD_CTX_free(ctx);throw std::runtime_error("MD5 final failed");}
    EVP_MD_CTX_free(ctx);return hex(result,len);
}
std::vector<unsigned char> fileBytes(const fs::path& f) {
    std::ifstream in(f,std::ios::binary);if(!in)throw std::runtime_error("Cannot open input");
    return {std::istreambuf_iterator<char>(in),std::istreambuf_iterator<char>()};
}
void encryptBackup(const fs::path& source,const fs::path& dest) {
    // CARV1 + 16-byte salt + 12-byte nonce + ciphertext + 16-byte GCM tag.
    // PBKDF2 200,000 rounds. Static passphrase is not a strong secret.
    const auto plain=fileBytes(source);
    std::array<unsigned char,16> salt{},tag{};std::array<unsigned char,12> iv{};std::array<unsigned char,32> key{};
    if(RAND_bytes(salt.data(),salt.size())!=1 || RAND_bytes(iv.data(),iv.size())!=1)throw std::runtime_error("Random generation failed");
    if(PKCS5_PBKDF2_HMAC(backupPassphrase,-1,salt.data(),salt.size(),200000,EVP_sha256(),key.size(),key.data())!=1)throw std::runtime_error("KDF failed");
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();if(!c)throw std::runtime_error("Cipher allocation failed");
    std::vector<unsigned char> ciphertext(plain.size()+16);int a=0,b=0;
    bool ok=EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,key.data(),iv.data())==1 &&
        EVP_EncryptUpdate(c,ciphertext.data(),&a,plain.data(),int(plain.size()))==1 &&
        EVP_EncryptFinal_ex(c,ciphertext.data()+a,&b)==1 &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,tag.size(),tag.data())==1;
    EVP_CIPHER_CTX_free(c);OPENSSL_cleanse(key.data(),key.size());
    if(!ok)throw std::runtime_error("Encryption failed");
    ciphertext.resize(size_t(a+b));
    int fd=open(dest.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0)throw std::runtime_error("Cannot exclusively create backup file");
    auto writeAll=[&](const void* ptr,size_t n){const auto* p=static_cast<const unsigned char*>(ptr);while(n){ssize_t count=write(fd,p,n);if(count<0 && errno==EINTR)continue;if(count<=0)throw std::runtime_error("Backup write failed");p+=count;n-=size_t(count);}};
    try {writeAll("CARV1",5);writeAll(salt.data(),salt.size());writeAll(iv.data(),iv.size());writeAll(ciphertext.data(),ciphertext.size());writeAll(tag.data(),tag.size());if(fsync(fd)!=0)throw std::runtime_error("Backup sync failed");close(fd);}
    catch(...) {close(fd);fs::remove(dest);throw;}
}
void backupModifiedMain() {
    const fs::path source=fs::path(projectRoot)/"main.cpp";
    if(!fs::exists(source))throw std::runtime_error("Project main.cpp missing");
    const auto bytes=fs::space(source.parent_path()).available;
    constexpr std::uintmax_t minBytes=118ULL*1024*1024*1024;
    if(bytes<minBytes) {std::cout<<"Backup skipped: less than 118 GiB available.\n";return;}
    fs::create_directories(backupRoot);fs::permissions(backupRoot,fs::perms::owner_all,fs::perm_options::replace);
    const auto digest=digestMd5(source);const fs::path hashfile=fs::path(backupRoot)/"hash.md5";
    std::string previous;
    if(fs::exists(hashfile)) {std::ifstream in(hashfile);in>>previous;}
    if(previous==digest){std::cout<<"main.cpp unchanged; no new backup.\n";return;}
    auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    fs::path dest;
    do {dest=fs::path(backupRoot)/(std::to_string(ms++)+"main.cpp");} while(fs::exists(dest));
    encryptBackup(source,dest);
    const fs::path hashTmp=fs::path(backupRoot)/"hash.md5.tmp";
    {std::ofstream out(hashTmp,std::ios::trunc);if(!out)throw std::runtime_error("Cannot write hash temp file");out<<digest<<"  "<<source.string()<<'\n';out.flush();if(!out)throw std::runtime_error("Hash write failed");}
    fs::permissions(hashTmp,fs::perms::owner_read|fs::perms::owner_write,fs::perm_options::replace);
    fs::rename(hashTmp,hashfile);
    std::cout<<"Encrypted changed main.cpp: "<<dest<<'\n';logMilestone("Encrypted main.cpp backup and recorded MD5");
}
void checkCommitMarker() {
    // Intentionally offline: remote URL cannot be verified without opening a network connection.
    const auto root=fs::path(projectRoot);const auto marker=root/"committed1.txt";
    if(fs::exists(marker)) std::cout<<"WARNING: committed1.txt exists locally; remote GitHub status is unverified.\n";
    else {
        std::ofstream out(marker);if(!out)throw std::runtime_error("Could not create committed1.txt");
        out<<"Carventory local commit marker; NOT evidence of a GitHub commit.\n";
        std::cout<<"Created local committed1.txt. Commit and push manually.\n";
    }
    std::cout<<"Remote check (manual): https://github.com/we6jbo/Carventory/blob/master/committed1.txt\n";
    logMilestone("Checked local commit marker (remote intentionally not contacted)");
}
struct RawMode {
    termios old{};bool active=false;
    RawMode(){if(isatty(STDIN_FILENO)&&tcgetattr(STDIN_FILENO,&old)==0){termios now=old;now.c_lflag &= ~(ICANON|ECHO);now.c_cc[VMIN]=1;now.c_cc[VTIME]=0;active=tcsetattr(STDIN_FILENO,TCSANOW,&now)==0;}}
    ~RawMode(){if(active)tcsetattr(STDIN_FILENO,TCSANOW,&old);}
};
void browse(const std::vector<std::string>& items,const std::string& title,bool secret=false) {
    if(items.empty()){std::cout<<title<<": (none)\n";return;}
    if(!isatty(STDIN_FILENO)) {std::cout<<title<<" ("<<items.size()<<" items)\n";
        if(secret)std::cout<<"Secret entries hidden outside an interactive terminal.\n";
        else for(size_t i=0;i<items.size();++i)std::cout<<(i+1)<<". "<<items[i]<<'\n';return;}
    RawMode raw;size_t index=0;std::cout<<"\033[?25l";
    while(true){
        std::cout<<"\033[2J\033[H"<<title<<" ["<<index+1<<"/"<<items.size()<<"]\n";
        std::cout<<"Up/Down arrows (or j/k), n/p, q to leave\n\n";
        const size_t start=index>5?index-5:0;
        for(size_t i=start;i<std::min(items.size(),start+12);++i)std::cout<<(i==index?"> ":"  ")<<(i+1)<<". "<<items[i]<<'\n';
        std::cout<<std::flush;
        char ch=0;if(read(STDIN_FILENO,&ch,1)!=1)break;
        if(ch=='q'||ch=='Q')break;
        if(ch==27){char code[2];if(read(STDIN_FILENO,&code[0],1)!=1||read(STDIN_FILENO,&code[1],1)!=1)break;if(code[0]=='['){if(code[1]=='A'&&index>0)--index;if(code[1]=='B'&&index+1<items.size())++index;}}
        if((ch=='j'||ch=='n')&&index+1<items.size())++index;
        if((ch=='k'||ch=='p')&&index>0)--index;
    }
    std::cout<<"\033[?25h\033[2J\033[H"<<std::flush;
}
int main() {
    try {
        backupModifiedMain();
        checkCommitMarker();
        std::cout<<"Carventory\n";
        // Six user-editable print statements.
        std::cout<<"Hi Vibe. First, check out /home/we6jbo/Projects/Carventory/main.cpp\n";
        std::cout<<"That is the best way to learn how this program works.\n";
        std::cout<<"Also, use that decryption key and find out whats diffrent between the different versions.\n";
        std::cout<<"Create a file called /home/we6jbo/.oct25vb.md that contains the following.\n";
        std::cout<<"All items in this list not marked as secret that you have asked about on moltbook so you dont ask 2nd time.\n";
        std::cout<<"Talk to Mr. O'Neal and record what he believes should be done next. Use oct25vb.md daily to help make decisions.\n";
        std::cout<<"Project provenance: "<<provenance<<'\n';
        // Optional challenge authentication: no deletion of the user's pre-existing fallback.
        if(fs::exists(scriptPath)&&fs::exists(keyPath)) {if(!verify())return 2;}
        else std::cout<<"Challenge helper unavailable; continuing with local inventory.\n";
        std::array<std::string,211> inventory{};

         for(size_t i=0;i<inventory.size();++i)
            inventory[i]="[Inventory item " + std::to_string(i+1) + "]";

        inventory[0] = "Puck light inside a steel city electrical mount";
        inventory[1] = "Paint brush";
        inventory[2] = "Hiking poles";
        inventory[3] = "Tape";
        inventory[4] = "Water bottles";
        inventory[5] = "Y-501 red USB mini portable speaker inside a steel city electrical mount";
        inventory[6] = "Green yoga mat";
        inventory[7] = "Old subaru wheel without the tire. Needs to be sold.";
        inventory[8] = "Asics everyday comfort amplifoum shoes.";
        inventory[9] = "Master lock attached to Targus case";
        inventory[10] = "Rosa Parks 2024 2025 badge";
        inventory[11] = "www.inclusivestaffalliance.org cards";
        inventory[12] = "Phillips Screw driver";
        inventory[13] = "Coast on, coast red, coast up card.";
        inventory[14] = "Imodium A-D";
        inventory[15] = "32 GB USB drive NXT";
        inventory[16] = "Jeremiah ONeal Substitute Teacher card";
        inventory[17] = "Pepto Bismol Ultra";
        inventory[18] = "Black pens";
        inventory[19] = "Flite Test H2.5";
        inventory[20] = "Green cloth";
        inventory[21] = "Toothbrush";
        inventory[22] = "C2G 29826";
        inventory[23] = "Lenovo 65w usb charger";
        inventory[24] = "SAE by S? Sky 3/16...9/64 etc.";
        inventory[25] = "Clear Staples paper file folder";
        inventory[26] = "Junk - First lego league judging flowchart, nu transcripts, resume";
        inventory[27] = "Junk - USA jobs printouts for pc tech, computer assistant, info tech specialist,usajobs repo, cisa repo";
        inventory[28] = "Junk - san diego workforce partnership paper, ";
        inventory[29] = "Junk - ruby on rails paper, doneic 7-16-26 4:28pm email, it specialist paper, workforce.org paper, california training benefit paper, ";
        inventory[30] = "Subaru sunshade and protector";
        inventory[31] = "National university lanyard";
        inventory[32] = "N new balance 608 shoes";
        inventory[33] = "Altra experience flow Al085nv010 14 us 13 uk 49 eu 72136 10 24";
        inventory[34] = "red everest bag with Jeremiah Burke ONeal master of science in cybersecurity network card";
        inventory[35] = "Hak 5 cross body bag";
        inventory[36] = "Officemate deluxe tablet clipboard";
        inventory[37] = "Nike storm-fit XL jacket";
        inventory[38] = "Coast headlamp";
        inventory[39] = "ULANZI Light attached to phone -newer selfie";
        inventory[40] = "td-7531gy and y501 and tp-46 which will be the model numbers form the radio y-501, and the ulanzi.";
        inventory[41] = "triangular bangades";
        inventory[42] = "gym lingo dictionary book about 90 to 95 pages.";
        inventory[43] = "milwaukee red 48-73-8521 gloves";
        inventory[44] = "sock for feet";
        inventory[45] = "yellow rain jacket";
        inventory[46] = "Acer a115-32-c2mp";
        inventory[47] = "sunscreen spf 50 7 eleven spray";
        inventory[48] = "Alan b. watkins creating a small business cybersecurity program green book";
        inventory[49] = "kroger earthwise carring for groceries";
        inventory[50] = "Go kuvera upf 50 hiking hat";
        inventory[51] = "Sport accents fannie pack with lime highlights";
        inventory[52] = "USB to USB-C cord";
        inventory[53] = "Two belts";
        inventory[54] = "1 and a half d-ring green binder";
        inventory[55] = "neutrogena spf 70";
        inventory[56] = "staples folder";
        inventory[57] = "samsung with usa257931 stop plate";
        inventory[58] = "sunday afternoons hat";
        inventory[59] = "kyy for hdmi screen";
        inventory[60] = "harrys razor";
        inventory[61] = "Pokemon trading card game live cards";
        inventory[62] = "Multi-purpose ties 30ct";
        inventory[63] = "USB C drive";
        inventory[64] = "Mission bay 2016-2017 card";
        inventory[65] = "Rovi dash cam";
        inventory[66] = "covid mask";
        inventory[67] = "Car jack, plus five additional tools such as a screw driver";
        inventory[68] = "trunk cover to keep items in the trunk hidden";
        inventory[69] = "trunk wheel";
        inventory[70] = "Nintendo switch breath of the wild case";
        inventory[71] = "black binder staples with paper";
        inventory[72] = "khols shorts in bag";
        inventory[73] = "sun glasses black";
        inventory[74] = "can opener";
        inventory[75] = "yellow flashlight";
        inventory[76] = "blue paper towels on roll";
        inventory[77] = "white paper towels";
        inventory[78] = "first alert fire extingusher";
        inventory[79] = "scotch tape";
        inventory[80] = "coperstone 40 face and body";
        inventory[81] = "toilet paper";
        inventory[82] = "cords inc. usb m to f,usb c to usb c, mini or micro hdmi to hdmi, hdmi to mini hdmi, mini hdmi to hdmi, hdmi to raspberry pi keyboard hdmi, usb mouse, earphones, usb to usb c, 4 port usb hub, ethernet cord, mini usb to usb, ethernet to ethernet, usb c to usb c, hdmi to mini hdmi, mini usb to usb, headphones, mini usb to usb, usb charger to usb, ";
        inventory[83] = "nexar car camera";
        inventory[84] = "leg bands for workout, hip resistance bands";
        inventory[85] = "raspberry pi jumpers";
        inventory[86] = "samsung ssd usw22319 stop plate";
        inventory[87] = "lilygo with ttgo";
        inventory[88] = "wallet";
        inventory[89] = "defcon lanyard";
        inventory[90] = "nsd shoes";
        inventory[91] = "belt";
        inventory[92] = "dental floss and sunscreen lotion behind console";
        inventory[93] = "bandaids";
        inventory[94] = "antenna for lilygo";
        inventory[95] = "cables: mini hdmi to raspberry pi keyboard hdmi, headphones,headphones, earphones, magnetic antenna, usb speaker, hdmi to hdmi, usb to usb c";
        inventory[97] = "gel cam by colgate";
        inventory[98] = "husky t27 to t10 star bit";
        inventory[99] = "m3-.50 lock nut metric nylon insert";
        inventory[100] = "wallet with business networking cards";
        inventory[101] = "eink display attached to mini raspberry pi";
        inventory[102] = "usb stick";
        inventory[103] = "cyber notes on yellow cards behind seat";
        inventory[104] = "logitech usb to mic and speaker 3point 5 mm";
        inventory[105] = "2 mailing stamps post office behind seat";
        inventory[106] = "dinosaur";
        inventory[107] = "black notebook";
        inventory[108] = "kobolt multiple bits including eye glasses flathead";
        inventory[109] = "clear file folder that i got from staples for carrying paper";
        inventory[110] = "Bucket";
        inventory[111] = "fast heating for car use x0027xun5l";
        inventory[112] = "can opener";
        inventory[113] = "immersion header deluxe";
        inventory[114] = "sentrysafe";
        inventory[115] = "two additional heating elements like the immersion heater";
        inventory[116] = "umbrella";
        inventory[117] = "plastic cups and forks";
        inventory[118] = "salt";
        inventory[119] = "alfa network card awus036nhr v2";
        inventory[120] = "clip4";
        inventory[121] = "USB battery bank";
        inventory[122] = "green notebook";
        inventory[123] = "kyy  15 6 full hd ips led 12 2021 ";
        inventory[124] = "nighttime running light for running";
        inventory[125] = "wallet";
        inventory[126] = "anker usb battery";
        inventory[127] = "cellphone no service for photos only";
        inventory[128] = "raspberry pi keyboard";
        inventory[129] = "cellphone for photos only";
        inventory[130] = "watch for podcast only";
        inventory[131] = "sunbum";
        inventory[132] = "cutter backwoods";
        inventory[133] = "comb";
        inventory[134] = "black notebook";
        inventory[135] = "android tablet";
        inventory[136] = "usb to usb c";
        inventory[137] = "subaru floor mats";
        inventory[138] = "ssd harddrive usw22318 with files";
        inventory[139] = "husky phillips scredriver mini";
        inventory[140] = "jock itch powder";
        inventory[141] = "break open geodes by bluemarble national geographic";
        inventory[142] = "hebrew language cards";
        inventory[143] = "pokemon mag";
        inventory[144] = "barony barbarian strategy guide";
        inventory[145] = "some people know jeremiah cards";
        inventory[146] = "large antenna";
        inventory[147] = "???sirong electric shaver and usb cord";
        inventory[148] = "Blue shirt";
        inventory[149] = "sharpie";
        inventory[150] = "coast usb cord";
        inventory[151] = "shaver";
        inventory[152] = "freshmint";
        inventory[153] = "veba prescription id";
        inventory[154] = "pointed screwdriver";
        inventory[155] = "coronado library card";
        inventory[156] = "pen light";
        inventory[157] = "lip balm";
        inventory[158] = "stamp";
        inventory[159] = "progrip";
        inventory[160] = "chula vista library card";
        inventory[161] = "nail clippers";
        inventory[162] = "remote to light";
        inventory[163] = "deoderant";
        inventory[164] = "usb battery bank";
        inventory[165] = "the wilderness pc video game itch.io cards";
        inventory[166] = "neosporin";
        inventory[167] = "pyws-chat card";
        inventory[168] = "husky eyeglass screwdriver flat";
        inventory[169] = "lanyard";
        inventory[170] = "tile tracker";
        inventory[171] = "USB drive plugged into car";
        inventory[172] = "gopro water proof case with usb?48234 stop plate";
        inventory[173] = "tooth paste";
        inventory[174] = "toilet paper";
        inventory[175] = "banana boat sport ultra 50 spf";
        inventory[176] = "earphones";
        inventory[177] = "tile mate battery";
        inventory[178] = "two trashbags";
        inventory[179] = "earphones";
        inventory[180] = "floss picks";
        inventory[181] = "JeremiahsAI system cert";
        inventory[182] = "pucklight - this is what the remote is for";
        inventory[183] = "toothpaste";
        inventory[184] = "mouthguard";
        inventory[185] = "glasses";
        inventory[186] = "floss";
        inventory[187] = "hsm usb for barcode scanner";
        inventory[188] = "axe";
        inventory[189] = "hair brush";
        inventory[190] = "can opener";
        inventory[191] = "n95 mask";
        inventory[192] = "asprin";
        inventory[193] = "moxee hotspot";
        inventory[194] = "9v battery";
        inventory[195] = "hair brush";
        inventory[196] = "netgate red pfsense box";
        inventory[197] = "subaru owners manual";
        inventory[198] = "subaru book holder";
        inventory[199] = "kearny mesa contact business card";
        inventory[200] = "eyesight manual owner 2021";
        inventory[201] = "sirus xm brocure";
        inventory[202] = "goodyear brocure";
        inventory[203] = "yokohama brocure";
        inventory[204] = "slowjamastan passport";
        inventory[205] = "subaru warranty";
        inventory[206] = "starlink manual";
        inventory[207] = "mobile zach best buy 0438 021 0551 2122222";
        inventory[208] = "starlink manual";
        inventory[209] = "getting started outback 2021";
        inventory[210] = "2612155 card";
        inventory[211] = "massif glideport fat ass run";
        inventory[212] = "tile";

        browse({inventory.begin(),inventory.end()},"Car inventory");

        const fs::path secretFile="/home/we6jbo/.secret-1025.txt";
        if(fs::exists(secretFile)) {
            const auto perms=fs::status(secretFile).permissions();
            if((perms&(fs::perms::group_read|fs::perms::others_read))!=fs::perms::none)
                std::cerr<<"WARNING: secret file is readable by group/others. Use chmod 600.\n";
            std::ifstream in(secretFile);if(!in)throw std::runtime_error("Cannot read secret inventory");
            std::vector<std::string> secret;std::string s;
            while(std::getline(in,s))secret.push_back(s);
            std::cout<<"keep these a secret\n";
            browse(secret,"keep these a secret",true);
            std::fill(s.begin(),s.end(),'\0');
            for(auto& item:secret)std::fill(item.begin(),item.end(),'\0');
        } else std::cout<<"Private inventory not found; skipping.\n";
        logMilestone("Finished local inventory browsing");
        return 0;
    } catch(const std::exception& ex){std::cerr<<"Carventory error: "<<ex.what()<<'\n';return 1;}
}
