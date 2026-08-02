// hello_stdio.c — demonstrates printf-like output via mini_stdio.h,
// still fully static (no dyld, no libSystem). Build with the same
// -nostdlib flags as hello.c; see build.sh.

#include "mini_stdio.h"

// No `naked` attribute, no separate static helper called via inline asm:
// referencing an internal function purely through inline-asm text (e.g.
// `bl _run`) is unreliable — the assembler/linker can't always prove the
// call site and the target are in the same section, and may emit an
// indirect stub through a pointer table instead of a direct branch (the
// exact same class of problem as needing dyld, just for an internal
// symbol). A plain C function avoids that entirely: 86arm's loader already
// sets up a valid SP before jumping to the entry point, so a normal
// prologue/epilogue is safe here.
void _start(void) {
    print_str("Hello, ");
    print_str("86arm");
    print_str("! The answer is ");
    print_int(42);
    print_str(" (0x");
    print_hex(42);
    print_str(").\n");
    sys_exit(0);
}