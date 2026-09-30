# Spicy notices (Linux Zeek packages)

The `zeek` binary in `installer/linux/zeek/zeek-core_*.deb` has the Spicy runtime built in. These are
`LICENSE` and `3rdparty/LICENSE.3rdparty` from zeek/spicy at commit
`63594ca470b215fa4c9f3363a5f337ed97e0e529`, the `auxil/spicy` submodule of Zeek v8.0.5. Replace them
from the new submodule commit whenever the bundled Zeek packages change.

`LICENSE.3rdparty` includes pathfind (LGPL). It is used only by Spicy's compiler tools, which the
packages do not ship; it is not in the `zeek` binary.

The Windows runtime was built without Spicy (`have_spicy=no`), so none of this applies there.
