// test_getpid.c — smallest possible real test of 86arm's thunk mechanism.
// Links libSystem NORMALLY (getpid() is a real reference, so the linker
// pulls in libSystem and emits a real LC_DYLD_CHAINED_FIXUPS bind entry
// for it) — but skips crt1.o's normal C-runtime startup by using a raw
// `_start` entry (like hello_stdio.c), so the ONLY external symbol this
// binary actually needs at runtime is `_getpid`. That isolates the test
// to exactly one thunk instead of the dozen-plus symbols a normal main()
// would pull in via crt startup.
//
// Build (see build.sh): needs -nostartfiles (skip crt1.o) + -Wl,-e,__start
// but NOT -nostdlib (we want libSystem actually linked this time).

#include <unistd.h>  // for getpid's prototype only

static void print_str(const char *s) {
    long len = 0;
    while (s[len]) len++;
    register long x0 __asm__("x0") = 1;
    register long x1 __asm__("x1") = (long)s;
    register long x2 __asm__("x2") = len;
    register long x16 __asm__("x16") = 4;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
}

static void print_int(long v) {
    char buf[24];
    int i = 0;
    if (v == 0) { print_str("0\n"); return; }
    unsigned long uv = (unsigned long)v;
    while (uv > 0) { buf[i++] = '0' + (uv % 10); uv /= 10; }
    char out[24];
    for (int j = 0; j < i; j++) out[j] = buf[i - 1 - j];
    out[i] = '\n';
    register long x0 __asm__("x0") = 1;
    register long x1 __asm__("x1") = (long)out;
    register long x2 __asm__("x2") = (long)(i + 1);
    register long x16 __asm__("x16") = 4;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
}

void _start(void) {
    print_str("calling real getpid() through the thunk...\n");
    pid_t p = getpid();  // real dynamic call — needs 86arm's thunk to work
    print_str("getpid() returned: ");
    print_int((long)p);

    register long x0 __asm__("x0") = 0;
    register long x16 __asm__("x16") = 1;
    __asm__ volatile("svc #0x80" :: "r"(x0), "r"(x16) : "memory");
}