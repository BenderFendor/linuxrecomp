/*
 * hybrid_selftest.c - the x87 half of the boundary, checked.
 *
 * The register half of hybrid is exercised by any project that uses it, and
 * loudly: get it wrong and nothing runs. The x87 half is not like that. Push
 * one value too few and a game computes with whatever was left in st(1); read
 * a depth wrong and the mistake surfaces eight calls later as a stack
 * overflow. So it gets a check.
 *
 *   cl /nologo hybrid_selftest.c hybrid.c && hybrid_selftest.exe
 */

#include <stdio.h>
#include <math.h>

#include "hybrid.h"

static int fails;

#define CHECK(cond) \
    do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d  %s\n", \
                                __FILE__, __LINE__, #cond); fails++; } } while (0)

int main(void)
{
    double got;
    unsigned short cw_before, cw_after;

    hybrid_fpu_clear();
    CHECK(hybrid_fpu_depth() == 0);

    /* Depth tracks pushes, and the query itself must not disturb them - it is
     * fnstenv, which empties nothing but masks every exception on the way. */
    {
        double two[2] = { 2.0, 10.0 };      /* st(0)=2.0, st(1)=10.0 */
        hybrid_fpu_push(two, 2);
        CHECK(hybrid_fpu_depth() == 2);
        CHECK(hybrid_fpu_depth() == 2);     /* still 2 after querying it */
        got = hybrid_fpu_pop();
        CHECK(got == 2.0);                  /* st(0) is two[0], not two[1] */
        CHECK(hybrid_fpu_depth() == 1);
        got = hybrid_fpu_pop();
        CHECK(got == 10.0);
        CHECK(hybrid_fpu_depth() == 0);
    }

    /* The control word has to survive both the depth query and the clear.
     * A game that asked for 24-bit precision - Direct3D used to, on every
     * device create - must not silently start computing in 53. */
    __asm { fnstcw cw_before }
    {
        unsigned short cw24 = (unsigned short)((cw_before & ~0x0300u) | 0x0000u);
        __asm { fldcw cw24 }
    }
    __asm { fnstcw cw_before }
    {
        double v[3] = { 1.0, 2.0, 3.0 };
        hybrid_fpu_push(v, 3);
        (void)hybrid_fpu_depth();
        hybrid_fpu_clear();
    }
    __asm { fnstcw cw_after }
    CHECK(cw_before == cw_after);
    CHECK(hybrid_fpu_depth() == 0);

    /* Restore a sane default for anything after this. */
    { unsigned short std_cw = 0x027F; __asm { fldcw std_cw } }

    /* The shape the whole thing exists for: MSVC's `_CIpow(x, y)` wants x in
     * st(1) and y in st(0) and returns in st(0). So pushing {y, x} is what a
     * lifted caller does, and popping in that order has to give y then x - the
     * push-order check above is exactly this property, spelled as the caller
     * will read it. */
    {
        double args[2] = { 10.0, 2.0 };     /* st(0)=y=10, st(1)=x=2 */
        double y, x;
        hybrid_fpu_push(args, 2);
        y = hybrid_fpu_pop();
        x = hybrid_fpu_pop();
        CHECK(y == 10.0 && x == 2.0);
        CHECK(pow(x, y) == 1024.0);
    }

    /* Eight is the whole file; a ninth push would fault, so the cap holds. */
    {
        double many[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        hybrid_fpu_push(many, 8);
        CHECK(hybrid_fpu_depth() == 8);
        hybrid_fpu_clear();
        CHECK(hybrid_fpu_depth() == 0);
    }

    if (fails) { fprintf(stderr, "%d check(s) failed\n", fails); return 1; }
    printf("ok: hybrid x87 depth, push order, pop, clear\n");
    return 0;
}
