
#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <cstddef>
#include <stdio.h>



// ============================================================================== //
// 类型缩写 types
// ============================================================================== //

typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef float f32;
typedef double f64;


u64 MASK(u64 n) {
    if (n == 64) return ~0ull;
    return (1ull << n) - 1ull;
}
u64 BITS(u64 imm, u64 hi, u64 lo) {
    return (imm >> lo) & MASK(hi - lo + 1ull);
}
u64 SEXT(u64 imm, u64 n) {
    if ((imm >> (n-1)) & 1) {
        printf("the src and res of sext are 0x%llx 0x%llx\n", (long long unsigned)imm, ((~0ull) << n) | imm);
        return ((~0ull) << n) | imm;
    } else return imm & MASK(n);
}


u64 imm_u(u32 inst) {return SEXT(BITS(inst, 31, 12), 20);}
u64 imm_j(u32 inst) {return (SEXT(BITS(inst, 31, 31), 1) << 20) | (BITS(inst, 30, 21) << 1) | (BITS(inst, 20, 20) << 11) | (BITS(inst, 19, 12) << 12);}
u64 imm_i(u32 inst) {return SEXT(BITS(inst, 31, 20), 12);}
u64 imm_s(u32 inst) {return SEXT((BITS(inst, 31, 25) << 5) | BITS(inst, 11, 7), 12); }
u64 imm_b(u32 inst) {return (SEXT(BITS(inst, 31, 31), 1) << 12) | (BITS(inst, 30, 25) << 5) | (BITS(inst, 11, 8) << 1) | (BITS(inst, 7, 7) << 11);}

/// 数组大小
#define ARRAY_SIZE(x)   (sizeof(x)/sizeof((x)[0]))

#endif // TYPES_H