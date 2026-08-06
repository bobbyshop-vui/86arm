// hello_math.c — demonstrates mini_math.h: real computation, no dyld/libm
// dependency at all. Build with the same flags as hello_stdio.c (see build.sh).

#include "mini_stdio.h"
#include "mini_math.h"

static void print_fixed(double v, int decimals) {
    // Minimal fixed-point printer (no float formatting in mini_stdio.h yet).
    if (v < 0) { putchar_m('-'); v = -v; }
    long ip = (long)v;
    print_int(ip);
    putchar_m('.');
    double frac = v - (double)ip;
    for (int i = 0; i < decimals; i++) {
        frac *= 10.0;
        int digit = (int)frac;
        putchar_m('0' + digit);
        frac -= digit;
    }
}

void _start(void) {
    print_str("sqrt(2)  = "); print_fixed(m_sqrt(2.0), 6); print_str("\n");
    print_str("sin(1.0) = "); print_fixed(m_sin(1.0), 6); print_str("\n");
    print_str("cos(1.0) = "); print_fixed(m_cos(1.0), 6); print_str("\n");
    print_str("exp(1.0) = "); print_fixed(m_exp(1.0), 6); print_str("\n");
    print_str("log(10)  = "); print_fixed(m_log(10.0), 6); print_str("\n");
    print_str("2^10     = "); print_fixed(m_pow(2.0, 10.0), 6); print_str("\n");
    sys_exit(0);
}