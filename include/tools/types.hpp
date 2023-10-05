
#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <cstddef>

/// 数组大小
#define ARRAY_SIZE(x)   (sizeof(x)/sizeof((x)[0]))

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

#endif // TYPES_H