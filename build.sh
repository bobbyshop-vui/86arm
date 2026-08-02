#!/bin/bash
# build.sh — fully local build, does not download anything from the network.
# Prerequisites: brew install unicorn ; pip3 install macholib ; nimble install nimpy
set -e

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

echo "== Done. Try: =="
echo "  ./bin/86arm --hello                  # built-in demo"
echo "  ./bin/86arm bin/hello_arm64           # real arm64 binary, just compiled"
echo "  ./bin/86arm bin/hello_stdio_arm64     # printf-like output via mini_stdio.h"