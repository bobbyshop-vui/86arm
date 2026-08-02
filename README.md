# 86arm

A tool to run ARM64 macOS (Mach-O) binaries on x86, using Unicorn Engine
as the CPU instruction emulator, written in Nim, FFI'd directly to libunicorn.

## Structure

```
86arm/
├── build.sh              # builds everything, fully local, no network access
├── src/
│   ├── main.nim           # CLI entrypoint + syscall translation table + loader
│   ├── unicorn_ffi.nim    # direct FFI binding to libunicorn (C)
│   └── machparse.nim      # real Mach-O parser, via nimpy + macholib (Python)
├── examples/
│   ├── hello.c             # hello world, compiled with clang -target arm64-apple-macos
│   ├── mini_stdio.h        # tiny statically-linked printf/file I/O shim (no dyld needed)
│   └── hello_stdio.c       # hello world using mini_stdio.h's printf
└── bin/                   # where build.sh puts the built binaries
```

## Install before building

```bash
brew install unicorn
pip3 install macholib
nimble install nimpy
```

## Build

```bash
./build.sh
```

This builds `bin/86arm`, and also compiles `examples/hello.c` and
`examples/hello_stdio.c` with **real clang**
(`clang -target arm64-apple-macos11`) into real ARM64 Mach-O binaries —
not mocks.

## Usage

```bash
86arm <arm64-file>              # quiet by default: only the process's own output is printed
86arm --verbose <arm64-file>    # also show loader/syscall diagnostics
86arm --trace <arm64-file>      # full per-instruction trace (implies --verbose)
86arm --hello                    # self-contained demo, no external file needed, always works
```

Example:

```bash
./bin/86arm --hello
./bin/86arm bin/hello_arm64
./bin/86arm bin/hello_stdio_arm64
```

## Always compile with `-fno-stack-protector`

Any function with a local array (like `print_uint`'s `char buf[32]`)
makes clang insert stack-protector code by default, even at `-O0`. That
code loads `__stack_chk_guard` through a GOT-style pointer that only
dyld would normally bind — in a `-nostdlib` binary it's just a null
pointer, so the first such function call crashes with a NULL dereference
(this is what actually caused the earlier "NULL deref, 8 bytes" crash —
not varargs, as first suspected). `build.sh` already passes
`-fno-stack-protector`; do the same for any new example you compile by hand.

## Why hello.c doesn't use `printf`/`stdio.h`

If it linked libSystem, the binary would need dyld to resolve `printf`
from an external dylib at startup — dyld emulation is **not implemented**
in this project. `hello.c` calls the `write`/`exit` syscalls directly via
inline asm instead, so it runs with just the minimal syscall table that
`main.nim` hooks.

## "Can it run stdio?"

Two different things hide behind that question:

- **Apple's real libSystem stdio (`printf` as normally linked)** — no.
  That requires dyld to resolve the symbol from a dylib at load time, and
  there is no dyld emulation here (see limitations below).
- **printf-like output with no dyld dependency at all** — yes, via
  `examples/mini_stdio.h`. It's a small statically-linked shim: `putchar`,
  `puts`, `print_str`/`print_int`/`print_uint`/`print_hex`/`print_char`
  (fixed-arity — no variadic `printf`, see note below), and thin
  `fopen`/`fread`/`fwrite`/`fclose` wrappers, all implemented directly on
  top of the syscalls 86arm already emulates. You `#include` it into your
  C file (not link) so the binary stays fully static. See `hello_stdio.c`
  for a working example.
- **Why no variadic `printf(fmt, ...)`**: a first version tried that and
  hit a real ABI landmine — clang's `va_arg` codegen on the
  `arm64-apple-macos` target dereferenced a NULL pointer inside a bare
  `-nostdlib` environment (confirmed by tracing the exact faulting
  address, not a guess). Apple's arm64 variadic calling convention needs
  more runtime scaffolding than this minimal setup provides. The
  fixed-arity `print_*` functions sidestep it entirely.

## Syscall translation table (current)

| XNU syscall | number | status |
|---|---|---|
| exit | 1 | implemented |
| read | 3 | implemented |
| write | 4 | implemented |
| open | 5 | implemented |
| close | 6 | implemented |
| getpid | 20 | implemented |
| munmap | 73 | implemented (no-op success — bump allocator can't really free) |
| mprotect | 74 | implemented |
| mmap | 197 | implemented, **anonymous mappings only** |
| lseek | 199 | implemented |

Numbers are taken from the real `bsd/kern/syscalls.master` in
apple-oss-distributions/xnu, which has been stable across XNU versions.

## Real limitations (not bugs — architectural)

- No dyld emulation. Any binary that depends on an external dylib
  (libSystem, Foundation, the Objective-C runtime...) will stop the
  moment it hits an unsupported instruction/syscall, not run "mostly".
  This is a categorically different, much larger undertaking than adding
  more syscalls — comparable in scope to projects like Darling, not
  something to bolt on incrementally.
- `machparse.nim` only reads `LC_SEGMENT_64` and `LC_MAIN`, not yet
  `LC_DYLD_INFO`, bind/rebase, or the symbol table.
- `mmap` only supports anonymous mappings; file-backed mmap returns an error.
- `munmap` doesn't actually free memory (bump allocator, no reuse).

This is a framework to extend incrementally, not a complete emulator.