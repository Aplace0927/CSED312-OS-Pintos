#ifndef THREADS_FP_ARITHMETIC_H
#define THREADS_FP_ARITHMETIC_H

#include <stdint.h>

#define F 14

#if F == 6  // [1, 9, 6]
    #define I 9
    #define fp_t int16_t
    #define fp_lt int32_t

    #define ONE_SIXTIETH 0x1                // ( 1/ 60) * (1 << 6) = 1.06666666667
    #define FIFTYNINE_SIXTIETH 0x63         // (59/ 60) * (1 << 6) = 62.9333333333

#elif F == 14   // [1, 17, 14]
    #define I 17
    #define fp_t int32_t
    #define fp_lt int64_t

    #define ONE_SIXTIETH 0x111              // ( 1/ 60) * (1 <<14) = 273.066666667
    #define FIFTYNINE_SIXTIETH 0x3EEF       // (59/ 60) * (1 <<14) = 16110.9333333

#elif F == 30   // [1, 33, 30]
    #define I 33
    #define fp_t int64_t
    #define fp_lt __int128_t

    #define ONE_SIXTIETH 0x1111111          // ( 1/ 60) * (1 <<30) = 17895697.0666
    #define FIFTYNINE_SIXTIETH 0x3EEEEEEF   // (59/ 60) * (1 <<30) = 1055846126.93

#endif

#define I2F 0b1 << F

fp_t integer_to_fixedpoint(int);

int fixedpoint_to_integer(fp_t);
int fixedpoint_round_integer(fp_t);

fp_t fixedpoint_add(fp_t, fp_t);
fp_t fixedpoint_sub(fp_t, fp_t);
fp_t fixedpoint_mul(fp_t, fp_t);
fp_t fixedpoint_div(fp_t, fp_t);
fp_t fixedpoint_mod(fp_t, fp_t);
fp_t fixedpoint_neg(fp_t);

#endif