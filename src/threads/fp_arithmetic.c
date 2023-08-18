#include "threads/fp_arithmetic.h"

fp_t
integer_to_fixedpoint (int i)
{
    return i << F;
}

int
fixedpoint_to_integer (fp_t f)
{
    return f >> F;
}

int
fixedpoint_round_integer (fp_t f)
{ 
    if (f >= 0)
    {
        return (f + (1 << (F - 1))) >> F;
    } 
    else
    {
        return (f - (1 << (F - 1))) >> F;
    }
}


fp_t
fixedpoint_add (fp_t x, fp_t y)
{
    return x + y;
}

fp_t
fixedpoint_sub (fp_t x, fp_t y)
{
    return x - y;
}

fp_t
fixedpoint_mul (fp_t x, fp_t y)
{
    return (((fp_lt) x) * y) >> F;
}

fp_t
fixedpoint_div (fp_t x, fp_t y)
{
    return (((fp_lt) x) << F) / y;
}

fp_t
fixedpoint_mod (fp_t x, fp_t y)
{
    return x % y;
}

fp_t
fixedpoint_neg (fp_t x)
{
    return x ^ (0b1 << (I + F));
}