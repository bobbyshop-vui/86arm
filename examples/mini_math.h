// mini_math.h — a tiny, statically-linked math library replacement.
//
// This is NOT Apple's real libm. Just like mini_stdio.h, it's meant to be
// #include'd directly into your C file (not linked), so the result stays
// a fully static binary with zero dyld dependency.
//
// Two kinds of functions here:
//   1. sqrt/fabs/floor/ceil/round/trunc/fmin/fmax — implemented via clang
//      __builtin_* intrinsics. On arm64 these compile straight down to a
//      single hardware FPU instruction (e.g. `fsqrt`) with NO function
//      call and NO library dependency at all — not even statically linked,
//      the "library" is just a CPU instruction.
//   2. sin/cos/exp/log/pow — no hardware instruction exists for these, so
//      they're implemented here as plain C (Taylor/Newton iteration).
//      Accuracy is good enough for general use (~1e-6 for the trig/exp
//      functions over a reasonable input range) but this is NOT a
//      drop-in replacement for libm's correctly-rounded implementations.
//
// IMPORTANT: compile with -fno-stack-protector (see README.md) — any
// function with a local array/buffer triggers clang's stack-protector,
// which needs dyld to resolve __stack_chk_guard and will NULL-deref
// without it. None of the functions below use local arrays, but keep
// the flag on any translation unit that includes this header alongside
// other code that does.

#ifndef MINI_MATH_H
#define MINI_MATH_H

// ---- hardware-instruction wrappers (zero dependency, not even static-lib) ----

static inline double m_sqrt(double x) { return __builtin_sqrt(x); }
static inline float  m_sqrtf(float x) { return __builtin_sqrtf(x); }
static inline double m_fabs(double x) { return __builtin_fabs(x); }
static inline double m_floor(double x) { return __builtin_floor(x); }
static inline double m_ceil(double x) { return __builtin_ceil(x); }
static inline double m_round(double x) { return __builtin_round(x); }
static inline double m_trunc(double x) { return __builtin_trunc(x); }
static inline double m_fmin(double a, double b) { return __builtin_fmin(a, b); }
static inline double m_fmax(double a, double b) { return __builtin_fmax(a, b); }
static inline double m_copysign(double x, double y) { return __builtin_copysign(x, y); }

// ---- hand-written transcendental functions (plain C, no builtins) ----

#define M_PI_M 3.14159265358979323846
#define M_E_M  2.71828182845904523536

// Range-reduce x into [-PI, PI] first for reasonable Taylor-series accuracy.
static inline double __reduce_angle(double x) {
    while (x > M_PI_M)  x -= 2.0 * M_PI_M;
    while (x < -M_PI_M) x += 2.0 * M_PI_M;
    return x;
}

static inline double m_sin(double x) {
    x = __reduce_angle(x);
    double term = x, sum = x, x2 = x * x;
    // Taylor series: x - x^3/3! + x^5/5! - x^7/7! + ...
    for (int n = 1; n <= 8; n++) {
        term *= -x2 / ((2 * n) * (2 * n + 1));
        sum += term;
    }
    return sum;
}

static inline double m_cos(double x) {
    x = __reduce_angle(x);
    double term = 1.0, sum = 1.0, x2 = x * x;
    // Taylor series: 1 - x^2/2! + x^4/4! - x^6/6! + ...
    for (int n = 1; n <= 8; n++) {
        term *= -x2 / ((2 * n - 1) * (2 * n));
        sum += term;
    }
    return sum;
}

static inline double m_tan(double x) {
    return m_sin(x) / m_cos(x);
}

static inline double m_exp(double x) {
    // e^x via Taylor series around 0; range-reduce using e^x = e^(x/2)^2
    // repeatedly to keep the series accurate for larger |x|.
    int reductions = 0;
    while (x > 1.0 || x < -1.0) { x *= 0.5; reductions++; }
    double term = 1.0, sum = 1.0;
    for (int n = 1; n <= 20; n++) {
        term *= x / n;
        sum += term;
    }
    while (reductions-- > 0) sum *= sum;
    return sum;
}

static inline double m_log(double x) {
    // Natural log via Newton's method on exp(y) = x, starting from a
    // cheap bit-level estimate of log2(x) to seed a good initial guess.
    if (x <= 0.0) return -1.0 / 0.0; // -inf, same convention as real log(0)
    double y = 0.0;
    double t = x;
    while (t > 2.0)  { t *= 0.5; y += 0.6931471805599453; }
    while (t < 0.5)  { t *= 2.0; y -= 0.6931471805599453; }
    // Newton iterations: y_{n+1} = y_n + (x*e^-y_n - 1)
    for (int i = 0; i < 10; i++) {
        double ey = m_exp(y);
        y += (x - ey) / ey;
    }
    return y;
}

static inline double m_pow(double base, double exp) {
    if (base <= 0.0) return m_exp(exp * m_log(base < 0 ? -base : base));
    return m_exp(exp * m_log(base));
}

#endif // MINI_MATH_H