#!/bin/bash
# build.sh — fully local build, does not download anything from the network.
# Prerequisites: brew install unicorn ; pip3 install macholib ; nimble install nimpy
set -e

# Respect DYLD_LIBRARY_PATH if the outer shell (zsh, etc.) already set it.
# Only fall back to asking python3 for its own lib dir if it's empty.
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    PY_LIBDIR="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR") or "")')"
    if [ -n "$PY_LIBDIR" ] && [ -d "$PY_LIBDIR" ]; then
        export DYLD_LIBRARY_PATH="$PY_LIBDIR"
    fi
fi

cd "$(dirname "$0")"

echo "== 1. Building the 86arm tool (Nim) =="
cd src
nim c -d:release -o:../bin/86arm --passL:"-lunicorn" main.nim
cd ..

echo "== 2. Compiling examples/hello.c into a real ARM64 Mach-O with clang =="
clang -target arm64-apple-macos11 -nostdlib -fno-stack-protector -Wl,-e,__start \
    -Wl,-undefined,dynamic_lookup \
    -o bin/hello_arm64 examples/hello.c

echo "== 3. Compiling examples/hello_stdio.c (mini_stdio.h demo) =="
clang -target arm64-apple-macos11 -nostdlib -fno-stack-protector -Wl,-e,__start \
    -Wl,-undefined,dynamic_lookup \
    -o bin/hello_stdio_arm64 examples/hello_stdio.c

echo "== 4. Compiling examples/hello_math.c (mini_math.h demo) =="
clang -target arm64-apple-macos11 -nostdlib -fno-stack-protector -Wl,-e,__start \
    -Wl,-undefined,dynamic_lookup \
    -o bin/hello_math_arm64 examples/hello_math.c

echo "== 5. Compiling examples/test_foundation.m (real Foundation binary, for --deps testing only) =="
clang -target arm64-apple-macos12 -isysroot $(xcrun --show-sdk-path) -framework Foundation \
    -o bin/test_foundation examples/test_foundation.m

echo "== 6. Reading test_foundation's real dyld bind table =="
./bin/86arm --deps bin/test_foundation

echo "== 7. Compiling examples/test_getpid.c (real thunk test — one symbol only) =="
clang -target arm64-apple-macos12 -isysroot $(xcrun --show-sdk-path) -fno-stack-protector -nostartfiles -Wl,-e,__start \
    -o bin/test_getpid_arm64 examples/test_getpid.c

echo "== 8. Running test_getpid_arm64 THROUGH 86arm's real emulator (not execCmd) =="
./bin/86arm --verbose bin/test_getpid_arm64

echo "== 9. Compiling examples/test_objc_new.m (isolated real objc_msgSend test) =="
clang -target arm64-apple-macos12 -isysroot $(xcrun --show-sdk-path) -fno-stack-protector \
    -nostartfiles -Wl,-e,__start -framework Foundation \
    -o bin/test_objc_new_arm64 examples/test_objc_new.m

echo "== 10. Running test_objc_new_arm64 THROUGH 86arm's real emulator =="
./bin/86arm --verbose bin/test_objc_new_arm64

echo "== 11. Running test_foundation THROUGH 86arm's own loader (thunk table now covers NSLog/Foundation directly — no native bridge, no temp files, no codesign) =="
./bin/86arm --verbose bin/test_foundation

echo "== 12. Compiling examples/test_nsarray.m (stress test: NSMutableArray, integer args/returns, void returns) =="
clang -target arm64-apple-macos12 -isysroot $(xcrun --show-sdk-path) -framework Foundation \
    -o bin/test_nsarray examples/test_nsarray.m

echo "== 13. Running test_nsarray THROUGH 86arm's own loader =="
./bin/86arm --verbose bin/test_nsarray

echo "== 14. Compiling examples/test_struct_return.m (stress test: NSRange struct-by-value return) =="
clang -target arm64-apple-macos12 -isysroot $(xcrun --show-sdk-path) -framework Foundation \
    -o bin/test_struct_return examples/test_struct_return.m

echo "== 15. Running test_struct_return THROUGH 86arm's own loader =="
./bin/86arm --verbose bin/test_struct_return

echo "== 16. Compiling examples/test_float.m (stress test: double argument + double return, via D0-D7) =="
clang -target arm64-apple-macos12 -isysroot $(xcrun --show-sdk-path) -framework Foundation \
    -o bin/test_float examples/test_float.m

echo "== 17. Running test_float THROUGH 86arm's own loader =="
./bin/86arm --verbose bin/test_float

echo "== Done. Try: =="
echo "  ./bin/86arm --hello                  # built-in demo"
echo "  ./bin/86arm bin/hello_arm64           # real arm64 binary, just compiled"
echo "  ./bin/86arm bin/hello_stdio_arm64     # printf-like output via mini_stdio.h"
echo "  ./bin/86arm bin/hello_math_arm64      # real math computation via mini_math.h"
echo "  ./bin/86arm --deps bin/test_foundation  # already ran above, rerun any time"
echo "  ./bin/86arm --verbose bin/test_getpid_arm64  # already ran above — real thunk test"
echo "  ./bin/86arm --verbose bin/test_foundation     # already ran above — real Foundation/NSLog via thunk table"