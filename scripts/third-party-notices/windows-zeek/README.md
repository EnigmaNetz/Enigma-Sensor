# Windows Zeek runtime notices

`installer/windows/zeek-runtime-win64.zip` is a custom Windows build of Zeek 8.0.0-dev.72 (May 2025),
built as documented in the Enigma-Zeek repository. Zeek's own `COPYING-3rdparty` (in `../zeek/`)
covers everything Zeek bundles, including c-ares, which this build compiled from `auxil/c-ares`.
The files here cover what the build linked from outside Zeek's source tree:

- OpenSSL 3.5.0, from the Chocolatey `openssl` package (`C:/Program Files/OpenSSL-Win64`)
- libpcap 1.10.5 and zlib 1.3.1, from vcpkg (Zeek's `vcpkg.json` at the time: c-ares, libpcap, zlib;
  ZeroMQ was not added until September 2025)
- the IPtoASN data file used by the ASN enrichment script

Versions are the ones embedded in `zeek.exe`. Update these files when the runtime is rebuilt.
`generate.sh` includes every `*.txt` here in name order.
