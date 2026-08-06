// test_objc_new.m — isolated test of the REAL objc_msgSend thunk.
// Raw `_start` entry (skips crt1.o's normal startup, like test_getpid.c),
// and deliberately avoids NSLog (variadic — a separate, already-documented
// ABI landmine, not related to objc_msgSend itself). This tests exactly
// one thing: does `[NSObject new]` — a 0-extra-args message send, which
// matches the shape 86arm's current objc_msgSend thunk handles — return a
// real, non-NULL object from the real host Objective-C runtime?
//
// Build: needs -framework Foundation (or -lobjc) + -nostartfiles -Wl,-e,__start
// + -fno-stack-protector, target macos12+ for chained fixups. See build.sh.

#import <Foundation/Foundation.h>

static void print_str(const char *s) {
    long len = 0;
    while (s[len]) len++;
    register long x0 __asm__("x0") = 1;
    register long x1 __asm__("x1") = (long)s;
    register long x2 __asm__("x2") = len;
    register long x16 __asm__("x16") = 4;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
}

void _start(void) {
    print_str("calling real objc_msgSend for [NSObject new]...\n");

    id obj = [NSObject new];  // objc_msgSend(NSObject-class, @selector(new)) — 0 extra args

    if (obj) {
        print_str("got a real object back — non-NULL!\n");
    } else {
        print_str("got NULL — objc_msgSend thunk or rebase is still wrong.\n");
    }

    register long x0 __asm__("x0") = 0;
    register long x16 __asm__("x16") = 1;
    __asm__ volatile("svc #0x80" :: "r"(x0), "r"(x16) : "memory");
}