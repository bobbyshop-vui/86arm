// examples/hello.c
// Cross-compiled to a real ARM64 Mach-O binary using clang directly on
// x86/Intel (clang on macOS always ships the arm64-apple-macos target —
// you don't need Apple Silicon to COMPILE it, only Apple Silicon or an
// emulator to RUN it natively).
//
// Deliberately no #include <stdio.h> / no libc: linking libSystem would
// require dyld to resolve printf from an external dylib, which 86arm does
// not emulate. Instead this calls write/exit directly via inline asm, so
// it runs with just the minimal syscall table main.nim already hooks
// (see README.md). For printf-like output without dyld, see
// mini_stdio.h + hello_stdio.c instead.

__attribute__((naked, noreturn))
void _start(void) {
    __asm__ volatile (
        "mov x0, #1                \n"   // fd = stdout
        "adrp x1, msg@PAGE          \n"   // page containing the string (PIC-safe on Mach-O)
        "add x1, x1, msg@PAGEOFF    \n"   // offset within the page
        "mov x2, #41                \n"   // string length
        "mov x16, #4                \n"   // syscall write (BSD number)
        "svc #0x80                  \n"
        "mov x0, #0                 \n"
        "mov x16, #1                \n"   // syscall exit
        "svc #0x80                  \n"
        ".section __TEXT,__cstring  \n"
        "msg: .asciz \"Hello from real clang-built ARM64 binary!\\n\"\n"
        ".text                      \n"
    );
}