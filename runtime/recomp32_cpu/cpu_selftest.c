/* cpu_selftest.c - check the CPU helpers against known-good values.
 *
 * These are bit operations where an off-by-one in a shift width produces
 * plausible-looking output rather than a crash, so they are worth pinning to
 * values worked out by hand. Rotates in particular are easy to get subtly
 * wrong: they do NOT touch ZF/SF/PF on x86, and a helper that sets them looks
 * fine until lifted code branches on a flag the previous instruction set.
 *
 *   cl /nologo cpu_selftest.c && cpu_selftest.exe
 *   cc -o cpu_selftest cpu_selftest.c && ./cpu_selftest
 */
#include <stdint.h>
#include <stdio.h>
#include "cpu.h"

static int fails;

static void eqf(const char *what, float got, float want)
{
    /* Compare the bit patterns, not the values: -0.0 == +0.0 is true in C and
     * the whole point of the min/max checks below is telling those apart. */
    uint32_t g, w;
    memcpy(&g, &got, 4); memcpy(&w, &want, 4);
    if (g != w) {
        printf("FAIL %-28s got %g (0x%08X) want %g (0x%08X)\n", what, got, g, want, w);
        fails++;
    }
}

static void eq(const char *what, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("FAIL %-28s got 0x%08X want 0x%08X\n", what, got, want);
        fails++;
    }
}

int main(void)
{
    CPU c = {0};

    /* rotates: 32-bit */
    eq("rol 0x12345678, 8", op_rol(&c, 0x12345678u, 8, 4), 0x34567812u);
    eq("ror 0x12345678, 8", op_ror(&c, 0x12345678u, 8, 4), 0x78123456u);
    eq("rol by 0 is identity", op_rol(&c, 0xDEADBEEFu, 0, 4), 0xDEADBEEFu);
    eq("rol by 32 is identity", op_rol(&c, 0xDEADBEEFu, 32, 4), 0xDEADBEEFu);

    /* rotates are width-sensitive: the same count differs per operand size */
    eq("rol 0x1234, 8 (16-bit)", op_rol(&c, 0x1234u, 8, 2), 0x3412u);
    eq("ror 0x12, 4 (8-bit)", op_ror(&c, 0x12u, 4, 1), 0x21u);

    /* a rotate must leave ZF alone - x86 does not set it here */
    c.zf = 1;
    (void)op_rol(&c, 0x00000001u, 1, 4);
    eq("rol preserves ZF", c.zf, 1);

    /* double-precision shifts */
    eq("shld F0F0F0F0 <- 0F0F0F0F, 4",
       op_shld(&c, 0xF0F0F0F0u, 0x0F0F0F0Fu, 4, 4), 0x0F0F0F00u);
    eq("shrd F0F0F0F0 <- 0F0F0F0F, 4",
       op_shrd(&c, 0xF0F0F0F0u, 0x0F0F0F0Fu, 4, 4), 0xFF0F0F0Fu);
    eq("shld by 0 is identity", op_shld(&c, 0xAAAAAAAAu, 0u, 0, 4), 0xAAAAAAAAu);

    /* segment registers exist and are 16-bit storage */
    c.ds = 0x1234; c.es = 0xFFFF; c.gs = 0x0007;
    eq("ds", c.ds, 0x1234u);
    eq("es", c.es, 0xFFFFu);
    eq("gs", c.gs, 0x0007u);

    /* ---- SSE ---- */

    /* The union really is one storage seen several ways - if it is not, every
     * movaps of a float mask silently corrupts something. */
    XMM x = {0};
    x.f32[0] = 1.0f;
    eq("xmm f32/u32 alias", x.u32[0], 0x3F800000u);

    /* A scalar load zeroes the rest of the register; a scalar reg-to-reg move
     * does not. Only the load has a helper, so only the load is checked here. */
    x.u64[0] = x.u64[1] = 0xAAAAAAAAAAAAAAAAull;
    sse_load_ss(&x, 2.0f);
    eq("movss load zeroes 32..63", x.u32[1], 0u);
    eq("movss load zeroes 64..127 lo", x.u32[2], 0u);
    eq("movss load zeroes 64..127 hi", x.u32[3], 0u);
    eqf("movss load keeps the value", x.f32[0], 2.0f);

    /* ucomiss sets the UNSIGNED flags - the compiler emits ja/jbe after a
     * float compare, never jg/jle - and an unordered compare sets all three,
     * which is what makes `ucomiss; jp` a NaN test. */
    sse_compare(&c, 2.0, 1.0);
    eq("ucomiss 2>1 zf", c.zf, 0u); eq("ucomiss 2>1 cf", c.cf, 0u);
    eq("ucomiss 2>1 pf", c.pf, 0u);
    sse_compare(&c, 1.0, 2.0);
    eq("ucomiss 1<2 cf", c.cf, 1u); eq("ucomiss 1<2 zf", c.zf, 0u);
    sse_compare(&c, 1.0, 1.0);
    eq("ucomiss 1==1 zf", c.zf, 1u); eq("ucomiss 1==1 cf", c.cf, 0u);
    c.sf = c.of = c.af = 1;
    sse_compare(&c, NAN, 1.0);
    eq("ucomiss NaN zf", c.zf, 1u);
    eq("ucomiss NaN pf", c.pf, 1u);
    eq("ucomiss NaN cf", c.cf, 1u);
    eq("ucomiss clears of", c.of, 0u);
    eq("ucomiss clears sf", c.sf, 0u);
    eq("ucomiss clears af", c.af, 0u);

    /* min/max are "if (dst OP src) dst else src", so the second operand wins
     * every tie. These four are the ones fmin/fmax get wrong. */
    eqf("minss(1,2)", sse_minf(1.0f, 2.0f), 1.0f);
    eqf("minss(2,1)", sse_minf(2.0f, 1.0f), 1.0f);
    eqf("minss(+0,-0) is src", sse_minf(0.0f, -0.0f), -0.0f);
    eqf("minss(-0,+0) is src", sse_minf(-0.0f, 0.0f), 0.0f);
    eqf("minss(NaN,3) is src", sse_minf((float)NAN, 3.0f), 3.0f);
    eqf("minss(3,NaN) is src", sse_minf(3.0f, (float)NAN), (float)NAN);
    eqf("maxss(1,2)", sse_maxf(1.0f, 2.0f), 2.0f);
    eqf("maxss(NaN,3) is src", sse_maxf((float)NAN, 3.0f), 3.0f);

    /* Out of range, x86 yields the integer indefinite rather than whatever a
     * C cast would have done - which is undefined and may trap. */
    eq("cvttss2si 3.9 truncates", (uint32_t)sse_cvtt_i32(3.9), 3u);
    eq("cvttss2si -3.9 truncates", (uint32_t)sse_cvtt_i32(-3.9), (uint32_t)-3);
    eq("cvttss2si 1e18 indefinite", (uint32_t)sse_cvtt_i32(1e18), 0x80000000u);
    eq("cvttss2si NaN indefinite", (uint32_t)sse_cvtt_i32(NAN), 0x80000000u);

    if (fails == 0)
        printf("cpu_selftest: all checks passed\n");
    return fails != 0;
}
