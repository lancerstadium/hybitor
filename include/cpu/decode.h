/**
 * @brief CPU 解码头文件
 * @file include/cpu/decode.h
 * @author lancerstadium
 * @date 2023-10-28
*/


#ifndef _HYBITOR_CPU_DECODE_H_
#define _HYBITOR_CPU_DECODE_H_

#include "isa.h"

// ============================================================================ //
// decode 结构体
// ============================================================================ //


/// @brief 解码器
typedef struct Decode {
    vaddr_t pc;     // 当前程序计数器：current pc
    vaddr_t snpc;   // 静态程序计数器：static next pc
    vaddr_t dnpc;   // 动态程序计数器：dynamic next pc
    ISADecodeInfo isa;  // 指令值
    IFDEF(CONFIG_ITRACE, char logbuf[128]);
} Decode;



// ============================================================================ //
// decode 宏定义 --> 实现：src/isa/ARCH/inst.c
// ============================================================================ //





__attribute__((always_inline))
/**
 * pattern matching mechanism
 * 用于将模式变量转换为三个整型字符串
*/
static inline void pattern_decode(const char *str, int len,
    uint64_t *key, uint64_t *mask, uint64_t *shift) {
  uint64_t __key = 0, __mask = 0, __shift = 0;
#define macro(i) \
  if ((i) >= len) goto finish; \
  else { \
    char c = str[i]; \
    if (c != ' ') { \
      Assertf(c == '0' || c == '1' || c == '?', \
          "invalid character '%c' in pattern string", c); \
      __key  = (__key  << 1) | (c == '1' ? 1 : 0); \
      __mask = (__mask << 1) | (c == '?' ? 0 : 1); \
      __shift = (c == '?' ? __shift + 1 : 0); \
    } \
  }

#define macro2(i)  macro(i);   macro((i) + 1)
#define macro4(i)  macro2(i);  macro2((i) + 2)
#define macro8(i)  macro4(i);  macro4((i) + 4)
#define macro16(i) macro8(i);  macro8((i) + 8)
#define macro32(i) macro16(i); macro16((i) + 16)
#define macro64(i) macro32(i); macro32((i) + 32)
    macro64(0);
    Fatal("pattern too long");
#undef macro
finish:
    *key = __key >> __shift;
    *mask = __mask >> __shift;
    *shift = __shift;
}

__attribute__((always_inline))
static inline void pattern_decode_hex(const char *str, int len,
    uint64_t *key, uint64_t *mask, uint64_t *shift) {
  uint64_t __key = 0, __mask = 0, __shift = 0;
#define macro(i) \
  if ((i) >= len) goto finish; \
  else { \
    char c = str[i]; \
    if (c != ' ') { \
      Assertf((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '?', \
          "invalid character '%c' in pattern string", c); \
      __key  = (__key  << 4) | (c == '?' ? 0 : (c >= '0' && c <= '9') ? c - '0' : c - 'a' + 10); \
      __mask = (__mask << 4) | (c == '?' ? 0 : 0xf); \
      __shift = (c == '?' ? __shift + 4 : 0); \
    } \
  }

  macro16(0);
  Fatal("pattern too long");
#undef macro
finish:
    *key = __key >> __shift;
    *mask = __mask >> __shift;
    *shift = __shift;
}



/**
 * @brief Instruction Patten 指令模式匹配宏：
 * `INSTPAT(模式字符串, 指令名称, 指令类型, 指令执行操作)`
 * @param 模式字符串 四种：`0`, `1`, `?`（0 或 1）, `<space>`（分隔）
 * @param 指令名称 在宏中作为注释
 * @param 指令类型 `U`, `I`, `S`, `N`, ...
 * @param 指令执行操作 寄存器、内存等等操作
*/
#define INSTPAT(pattern, ...) do { \
  uint64_t key, mask, shift; \
  pattern_decode(pattern, STRLEN(pattern), &key, &mask, &shift); \
  if ((((uint64_t)INSTPAT_INST(s) >> shift) & mask) == key) { \
    INSTPAT_MATCH(s, ##__VA_ARGS__); \
    goto *(__instpat_end); \
  } \
} while (0)

/**
 * 
*/
#define INSTPAT_START(name) { const void ** __instpat_end = &&concat(__instpat_end_, name);


#define INSTPAT_END(name)   concat(__instpat_end_, name): ; }


// ============================================================================ //
// isa API 实现 --> 声明：include/cpu/decode.h
// ============================================================================ //

/// @brief isa执行一次
/// @param s 解码器
int isa_exec_once(Decode *s);

/// @brief isa取指令一次
/// @param s 解码器
/// @param next_inst_len 下条指令长度
void isa_fetch_once(Decode *s, int next_inst_len);

#endif  // _HYBITOR_CPU_DECODE_H_