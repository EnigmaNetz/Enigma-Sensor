# Windows Zeek runtime notices

`installer/windows/zeek-runtime-win64.zip` is a Windows build of Zeek 8.0.10, built and published by
the Enigma-Zeek repository (release `zeek-runtime-win64-v8.0.10-r2`; its `BUILD-INFO.txt` records the
commits used). Zeek's own `COPYING-3rdparty` (in `../zeek/`) covers everything Zeek bundles,
including c-ares, which this build compiles from Zeek's `auxil/c-ares`. The build gets its other
libraries from vcpkg (Zeek's `auxil/vcpkg`, pinned in Enigma-Zeek) and links them statically; the
files here cover those: OpenSSL 3.6.3, libpcap 1.10.6 and zlib 1.3.2.

The ZeroMQ cluster backend is left out of the build, so libzmq and libsodium are not in `zeek.exe`.

Versions are the ones embedded in `zeek.exe`. Update these files when the runtime is rebuilt.
`generate.sh` includes every `*.txt` here in name order.
