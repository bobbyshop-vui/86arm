// mini_stdio.h — a tiny, statically-linked stdio replacement.
//
// This is NOT Apple's real libSystem stdio. It never touches dyld: every
// function here is implemented directly on top of the raw XNU syscalls
// that 86arm already emulates (write, read, open, close). Compile it
// straight into your program's translation unit (#include, not link) and
// the resulting binary stays fully static — no dylib dependency at all.
//
// Supported: putchar, puts, print_str/print_int/print_uint/print_hex/
// print_char (fixed-arity, see note below), fopen/fread/fwrite/fclose
// (thin wrappers over open/read/write/close).
//
// NOTE ON VARARGS: there is deliberately no variadic printf(fmt, ...) here.
// A first version tried that and it hit a real ABI landmine on the
// arm64-apple-macos target: clang's va_arg codegen dereferenced a NULL
// pointer when run in a bare -nostdlib environment (confirmed by tracing
// the actual faulting address, not a guess). Apple's arm64 variadic
// calling convention needs more runtime scaffolding than this minimal
// setup provides. The fixed-arity functions below take arguments in plain
// registers — no va_list involved — so they work by construction.

#ifndef MINI_STDIO_H
#define MINI_STDIO_H

typedef unsigned long size_t_m;
typedef long ssize_t_m;

// ---- raw syscalls (arm64, XNU ABI: args in x0-x5, number in x16, svc #0x80) ----

static inline long __sys3(long num, long a0, long a1, long a2) {
    register long x16 __asm__("x16") = num;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x16) : "memory");
    return x0;
}

static inline ssize_t_m sys_write(int fd, const void *buf, size_t_m n) {
    return __sys3(4, fd, (long)buf, (long)n);
}
static inline ssize_t_m sys_read(int fd, void *buf, size_t_m n) {
    return __sys3(3, fd, (long)buf, (long)n);
}
static inline int sys_open(const char *path, int flags, int mode) {
    return (int)__sys3(5, (long)path, flags, mode);
}
static inline int sys_close(int fd) {
    return (int)__sys3(6, fd, 0, 0);
}
static inline void sys_exit(int code) {
    __sys3(1, code, 0, 0);
    __builtin_unreachable();
}

// ---- putchar / puts ----

static inline int putchar_m(char c) {
    sys_write(1, &c, 1);
    return (unsigned char)c;
}

static inline int puts_m(const char *s) {
    size_t_m n = 0;
    while (s[n]) n++;
    sys_write(1, s, n);
    putchar_m('\n');
    return (int)n + 1;
}

// ---- fixed-arity print functions (no C varargs machinery at all) ----
//
// A variadic printf_m was tried here first and hit a real toolchain/ABI
// landmine: on the arm64-apple-macos target, clang's __builtin_va_arg
// codegen dereferenced a NULL pointer inside a bare -nostdlib environment
// (confirmed via a memory-fault trace, not a guess). Apple's arm64 varargs
// convention apparently needs more runtime scaffolding than this minimal
// setup provides. Rather than keep guessing against an ABI corner case,
// these functions take fixed arguments (passed in registers, no va_list
// involved at all) and are guaranteed to work by construction.

static inline void print_str(const char *s) {
    while (*s) putchar_m(*s++);
}

static inline void print_uint(unsigned long v, int base, int upper) {
    char buf[32];
    int i = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    if (v == 0) { putchar_m('0'); return; }
    while (v > 0) { buf[i++] = digits[v % (unsigned)base]; v /= (unsigned)base; }
    while (i > 0) putchar_m(buf[--i]);
}

static inline void print_int(long v) {
    if (v < 0) { putchar_m('-'); print_uint((unsigned long)(-v), 10, 0); }
    else       { print_uint((unsigned long)v, 10, 0); }
}

static inline void print_hex(unsigned long v) { print_uint(v, 16, 0); }
static inline void print_char(char c) { putchar_m(c); }

// ---- tiny file I/O ----

typedef struct { int fd; } FILE_m;

static inline FILE_m *fopen_m(const char *path, int flags, int mode) {
    static FILE_m f; // single global handle; extend to a real table if you need more than 1
    int fd = sys_open(path, flags, mode);
    if (fd < 0) return 0;
    f.fd = fd;
    return &f;
}
static inline size_t_m fread_m(void *buf, size_t_m n, FILE_m *f) {
    ssize_t_m r = sys_read(f->fd, buf, n);
    return r < 0 ? 0 : (size_t_m)r;
}
static inline size_t_m fwrite_m(const void *buf, size_t_m n, FILE_m *f) {
    ssize_t_m r = sys_write(f->fd, buf, n);
    return r < 0 ? 0 : (size_t_m)r;
}
static inline void fclose_m(FILE_m *f) {
    sys_close(f->fd);
}

#endif // MINI_STDIO_H