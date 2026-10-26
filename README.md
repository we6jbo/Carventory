# Carventory 0.2 (terminal only)

Carventory is an offline CLI inventory browser, with 100 starter item labels and an optional private line-oriented file at `/home/we6jbo/.secret-1025.txt`.

## Safety notes
- The requested encryption passphrase is hardcoded in main.cpp and so must not be treated as confidential. Backups use AES-256-GCM and PBKDF2-HMAC-SHA256; treat encrypted copies as *obfuscation against casual reading*, not protection from someone with source or binary access.
- `hash.md5` is a change detector, not an authentication mechanism.
- Backups need **118 GiB available** on the project filesystem; otherwise backup is skipped and inventory continues.
- The GitHub marker is checked *locally only*: no outbound connections are made. A marker does not prove a push to GitHub.
- The secret file is read and displayed only in an interactive terminal. Do not insert actual card numbers or license numbers unless truly necessary; anyone watching the screen can read them. The file is never packaged.
- Optional `/usr/local/bin/challenge.sh` HMAC verification runs when both the helper and key exist; otherwise inventory still works.

## Build
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2`

## Run
`./build/Carventory`

Identifiers: TG333041 and TG654147. The snapshot is portable and needs no local database.
