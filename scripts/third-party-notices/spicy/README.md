# Spicy notices (Linux Zeek packages)

The `zeek` binary in `installer/linux/zeek/ubuntu-*/zeek-lts-core_*.deb` has the Spicy runtime built in. These are
`LICENSE` and `3rdparty/LICENSE.3rdparty` from zeek/spicy at commit
`c776344c97c14778ba9e23b2d15b0ad73d59dd4e`, the `auxil/spicy` submodule of Zeek v8.0.10. Replace them
from the new submodule commit whenever the bundled Zeek packages change.

`LICENSE.3rdparty` includes pathfind (LGPL). It is used only by Spicy's compiler tools, which the
packages do not ship; it is not in the `zeek` binary.

The Windows runtime is built without Spicy (`spicy: disabled` in its `BUILD-INFO.txt`), so none of this applies there.
