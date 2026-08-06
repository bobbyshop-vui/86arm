# 86arm

Run **real ARM64 macOS (Mach-O) binaries** on an **x86 Mac**, by emulating
the ARM64 CPU with [Unicorn Engine](https://www.unicorn-engine.org/),
written in Nim, FFI'd directly to `libunicorn`.

This is **not** Rosetta 2 (Rosetta translates the other direction: x86 →
ARM64, to run old Intel apps on Apple Silicon). 86arm does the direction
almost nobody needs — running ARM64 binaries on an Intel machine — so
there's essentially no existing tool to build on; everything here is
written from scratch.

## Core idea

86arm does **not** try to re-emulate all of macOS (real dyld, real ObjC
runtime, real Foundation/AppKit...). Instead, it leans on the host machine,
which already has all of that:

1. Parse the Mach-O (`machparse.nim`) to find out which external dylib
   symbols the binary needs (via `LC_DYLD_CHAINED_FIXUPS`).
2. For each symbol needed, `dlopen`/`dlsym` the **real** system dylib
   (`libobjc.A.dylib`, `Foundation.framework`...) right inside the `86arm`
   process itself (the host), not inside the guest.
3. Patch the guest's GOT slot for that symbol to point at a **thunk**
   address (in the fake `0x300000000` range) instead of a real address.
4. When Unicorn's emulation reaches a jump into that thunk, `86arm`
   intercepts it, reads the arguments straight out of the guest's
   registers/stack, calls the **real host function**, writes the result
   back into the guest's registers, and lets emulation continue.

In short: **guest code (ARM64) runs inside Unicorn, while the real
frameworks (the ObjC runtime, Foundation...) run for real on the host
(x86); 86arm is the bridge in between.**

## Structure

```
86arm/
├── build.sh                 # builds everything and runs all the tests, no network needed
├── src/
│   ├── main.nim              # CLI, Mach-O loader, thunk table, dispatch
│   ├── unicorn_ffi.nim       # direct FFI binding to libunicorn (C)
│   ├── machparse.nim         # real Mach-O parser (via nimpy + macholib)
│   └── objc_ffi.nim          # libffi + Objective-C runtime introspection bridge
├── examples/                 # test binaries, compiled for real with clang
└── bin/                      # where build.sh puts the built binaries
```

### `main.nim` — loader + thunk table

- Parses the Mach-O, maps its segments into Unicorn's memory.
- `thunkTable`: maps a symbol name (`_getpid`, `_objc_msgSend`, `_NSLog`...)
  to a Nim closure; that closure reads the guest's registers/stack, calls
  the real host function, and writes the result back.
- `resolveDataSymbol`: handles symbols that are **data**, not functions —
  e.g. `_OBJC_CLASS_$_NSString` (a real class pointer) or
  `___CFConstantStringClassReference` (the `isa` of an `@"..."` literal).

### `objc_ffi.nim` — the part that makes this actually general

This is what turns 86arm from "knows how to call a handful of hardcoded
functions" into "can call **any** Objective-C selector with a compatible
signature," by asking the real runtime directly:

- `method_getReturnType` / `method_getArgumentType` /
  `method_getNumberOfArguments` — the real runtime already knows the exact
  return type and every argument type of any method, no prior knowledge
  needed.
- A recursive parser reads that `@encode` string (including nested structs
  like `{CGRect={CGPoint=dd}{CGSize=dd}}`) and builds a matching `ffi_type`
  descriptor using libffi's real struct layout.
- **libffi** (`ffi_prep_cif`/`ffi_call`) builds the actual call according
  to the real host ABI, instead of hand-coding every call shape.
- Arguments are read from the correct **AAPCS64** register bank: `X2-X7`
  for pointers/integers, `D0-D7` for `float`/`double` — two **independent**
  counters.
- `callVariadicHostFn`: calls a real variadic C function (like `NSLog`)
  with a caller-chosen type per argument — needed because a
  `printf`-style variadic call has to know each argument's type ahead of
  time to route it to the right register bank (GP vs FP).

## What works (tested for real, with real logs)

| Feature | Status |
|---|---|
| Basic syscalls (`write`, `read`, `open`, `getpid`, `mmap`...) | ✅ |
| `printf`-style output with no dyld dependency (`mini_stdio.h`) | ✅ |
| Math with no `libm` dependency (`mini_math.h`) | ✅ |
| Calling `objc_msgSend` for **any selector** whose args/return are object, integer (8/16/32/64-bit), `char*`, or a generic pointer | ✅ (via libffi + runtime introspection) |
| `float`/`double` arguments/returns | ✅ (via `D0-D7`) |
| Struct **returns** up to 16 bytes, all-integer fields (e.g. `NSRange`) | ✅ |
| `NSLog` with multiple varargs of any type (`%@`, `%lu`, `%f`...) | ✅ (parses the real format string, routes each argument correctly) |
| Basic Foundation: `NSString`, `NSMutableArray`, `@autoreleasepool` | ✅ |

Tests live in `examples/` — running `./build.sh` builds and runs all of
them, printing `--verbose` logs for each step.

## What doesn't work yet (real limits, not bugs)

| Missing | Why | Patchable? |
|---|---|---|
| Struct **arguments** (`initWithFrame:` taking an `NSRect`) | Needs packing struct fields into the right GP/FP registers when passing *in*, the reverse direction of the struct-return support already built | Yes, not done yet |
| Structs with `float`/`double` fields over 8 bytes, or struct returns over 16 bytes (`CGRect`, `CGSize`) | AAPCS64 uses HFA rules (all in `D0-D3`) or an indirect convention via a hidden `X8` pointer — different from the `X0/X1` mechanism already built | Yes, not done yet |
| Block callbacks (`^{...}`) | Needs a real host-side closure via `ffi_closure` so the host can call back into guest code | Meaningfully harder, not done |
| Arbitrary variadic C functions (beyond the hand-patched `NSLog`) | No `method_getArgumentType`-equivalent exists for plain C functions — can't ask the runtime | Has to be hand-patched per function |
| Real AppKit UI actually appearing on screen | Needs a real run loop and a real WindowServer connection over Mach IPC — a different category of problem than "can call the function" | Not a patch — needs different architecture |
| File-backed `mmap`, real dyld, complex post-rebase writable `__DATA` | Outside the loader's original scope | Out of scope |

## Building

Prerequisites (install once, no network needed for builds after that):

```bash
brew install unicorn
pip3 install macholib
nimble install nimpy
```

Build and run all tests:

```bash
./build.sh
```

`build.sh` doesn't download anything — it just uses the `clang` already on
your machine to compile the `.m`/`.c` files in `examples/` into real ARM64
binaries, then runs them through `bin/86arm`.

## Usage

```bash
86arm <arm64-file>              # run it, only the program's own output is printed
86arm --verbose <arm64-file>    # also print loader/thunk/bind diagnostics
86arm --trace <arm64-file>      # print every guest instruction (very verbose, debug only)
86arm --deps <arm64-file>       # read the real bind table (doesn't run it)
86arm --hello                   # self-contained demo, no external file needed
```

## Development history (summary)

This project was built up over many real debugging rounds, each diagnosed
from real logs/`otool`/`--trace` output rather than guesswork:

1. **The original fatal bug**: the entire `main` logic was mis-indented,
   accidentally nested inside a different proc's body — the program built
   fine but did nothing at all when run.
2. **`execCmd` dropped `DYLD_INSERT_LIBRARIES`**: macOS SIP strips `DYLD_*`
   environment variables when loading `/bin/sh` (a protected system
   binary) — fixed by exec'ing directly, with no shell in between.
3. Dropped the "native bridge" approach entirely (cputype-spoofing +
   `mprotect` + signal handler, aah-style) after realizing guest code
   could run straight through the thunk mechanism, with no need for real
   dyld to ever load the binary on the host.
4. Added `libffi` + Objective-C runtime introspection to generalize
   `objc_msgSend` calls, instead of guessing arity by counting colons in
   the selector name.
5. Found that `_objc_autoreleasePoolPush`/`Pop` had no thunk wired up, so
   the guest jumped into an unpatched GOT slot value and crashed.
6. Discovered that calling `objc_msgSend` through a direct `{.cdecl.}`
   function-pointer cast returned garbage values on the real machine —
   switched entirely to calling through `libffi` instead.
7. Used `otool -tv` to disassemble the real binary and discovered
   `NSLog`'s vararg is passed on the **stack** (`[sp+0]`), not in register
   `X1` as originally assumed.
8. Added struct-return support (`NSRange`) via a recursive parser that
   reads the real `@encode` string.
9. Added `float`/`double` support after the user compiled a small C
   program to get the **real** `D0-D7` register values from their
   installed `libunicorn` (not guessed).
10. Found that `NSLog("%f", ...)` printed `0.000000` because a `double`
    vararg was being forced through an integer register instead of
    `XMM`/FP — fixed by parsing the real format string's conversion
    characters (`%f` vs `%@` vs `%lu`...) and calling through libffi with
    the correct type per argument.

## License / notes

Personal project, not affiliated with Apple. Uses the system's existing
`libunicorn` (GPLv2) and `libffi` (MIT) — nothing is downloaded or bundled.