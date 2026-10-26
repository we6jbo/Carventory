# Carventory — terminal vehicle inventory

Carventory is an offline C++ terminal inventory browser. The regular inventory is defined in `main.cpp`. A separate optional private inventory is read, one line per item, from `/home/we6jbo/.secret-1025.txt` on the T14. That private file is never bundled with the project.

## Build and run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 2
./build/Carventory
```

Navigate with up/down arrows (or j/k). Press `q` to finish the regular inventory; if the private file exists, the private inventory follows. Press `q` again to exit.

## Backup and privacy

When at least **109 GiB** is available and `main.cpp` has changed according to its MD5 record, the T14 build creates an encrypted source backup under `~/.forvibe-102526/`. This is a change-detection backup, not a validated full restoration solution. The encryption passphrase is hardcoded in the public source; anyone with the source and backup can derive the decryption key. Do not rely on it to protect sensitive information.

Carventory may show private inventory entries on-screen in an interactive terminal. Do not commit your `.secret-1025.txt`, backup files, or other private documents.

If present, the external challenge helper is verified at startup. The GitHub commit-marker check is local only; it does not verify the state of GitHub.

## Desktop / Flatpak metadata

The `.desktop` launcher sets `Terminal=true` because Carventory is a command-line application. Terminal handling varies across desktop environments and Flatpak deployments. A working local Flatpak build does **not** establish Flathub acceptance; verify launcher behavior and applicable Flathub rules before submission. The current source also contains T14-specific absolute paths that limit portability.

## Project identification

Provenance identifiers: `TG333041`, `TG654147`. See `tg_context_snapshot.json`.

AI-assisted development is disclosed in `AI-DISCLOSURE.txt`. Source license: Apache-2.0 (see `LICENSE`).
