#!/bin/bash
# run.sh — launch 86arm with ONLY libpython visible (the LIEF-based Mach-O
# parser needs it). Exposing the whole python lib dir via DYLD_LIBRARY_PATH
# shadows system libs (e.g. libiconv) and crashes AppKit/Foundation loading.
D="$(cd "$(dirname "$0")" && pwd)"
PYLIB="$(python3 -c 'import sysconfig,os;print(os.path.join(sysconfig.get_config_var("LIBDIR"),"libpython"+sysconfig.get_config_var("py_version_short")+".dylib"))')"
mkdir -p "$D/.pylib" && ln -sf "$PYLIB" "$D/.pylib/$(basename "$PYLIB")"
DYLD_LIBRARY_PATH="$D/.pylib" exec "$D/bin/86arm" "$@"
