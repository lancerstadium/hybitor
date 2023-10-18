/**
 * @brief hybitor debugger 的表达式解析器
 * @file src/monitor/hdb/expr.c
 * @author lancerstadium
 * @date 2023-10-16
*/

#include "hdb.h"
#include "common.h"
#include <regex.h>



// ============================================================================ //
// expr 静态变量
// ============================================================================ //

/// @brief 表达式 token 类型
enum {
    TK_NOTYPE = 256, TK_EQ,
    /// TODO: Add more token types 

};

/// @brief 表达式规则映射：表达式语句 --> token 类型编号
static struct rule {
    const char *regex;      // 表达式语句
    int token_type;         // token 类型编号
} rules[] = {
    /// TODO: Add more rules, Pay attention to the precedence level of different rules.
    {" +", TK_NOTYPE},    // spaces
    {"\\+", '+'},         // plus
    {"==", TK_EQ},        // equal
};

/// @brief 表达式规则数量
#define NR_REGEX ARRLEN(rules)

/// @brief 表达式结构体数组
static regex_t re[NR_REGEX] = {};

/// @brief 表达式 token 结构体
typedef struct token {
    int type;       // 类型编号
    char str[32];   // 字符串
} Token;

// `__attribute__((used))`通知编译器在目标文件中保留一个静态变量，即使它没有被引用。

/// @brief token 结构体数组
static Token tokens[32] __attribute__((used)) = {};

/// @brief 表达式 token 长度
static int nr_token __attribute__((used))  = 0;

// ============================================================================ //
// expr 内部静态函数
// ============================================================================ //

/// @brief 将字符串转换成 token
/// @param e 字符串
/// @return 是否成功转换成 token
static bool make_token(char *e) {
    int position = 0;
    int i;
    regmatch_t pmatch;  // 匹配结果
    nr_token = 0;

    // 遍历字符串
    while (e[position] != '\0') {
        // 遍历规则数组
        for (i = 0; i < NR_REGEX; i++) {
            if (regexec(&re[i], e + position, 1, &pmatch, 0) == 0 && pmatch.rm_so == 0) {
                char *substr_start = e + position;  // 匹配起始位置
                int substr_len = pmatch.rm_eo;     // 匹配长度
                // 打印匹配结果
                Logw("match rules[%d] = \"%s\" at position %d with len %d: %.*s",
                    i, rules[i].regex, position, substr_len, substr_len, substr_start);
                // 移动位置指针
                position += substr_len;

                /** TODO: Now a new token is recognized with rules[i]. Add codes
                 * to record the token in the array `tokens'. For certain types
                 * of tokens, some extra actions should be performed.
                 */

                switch (rules[i].token_type) {
                case TK_NOTYPE: TODO("token_type: NoType"); break;
                case TK_EQ: TODO("token_type: TK_EQ"); break;
                default: TODO("token_type: default"); 
                }
                break;
            }
        }
        // 没有匹配
        if (i == NR_REGEX) {
            Errorf("no match at position %d\n%s\n%*.s^\n", position, e, position, "");
            return false;
        }
    }
    return true;
}

// ============================================================================ //
// expr API 实现 --> 定义 src/monitor/hdb/hdb.h
// ============================================================================ //

void init_regex() {
    char error_msg[128];
    int ret;

    int i;
    for (i = 0; i < NR_REGEX; i++) {
        ret = regcomp(&re[i], rules[i].regex, REG_EXTENDED);
        if (ret != 0) {
            regerror(ret, &re[i], error_msg, 128);
            Errorf("regex compilation failed: %s\n%s", error_msg, rules[i].regex);
        }
    }
    Logg("Init regex: rules' number: %d", NR_REGEX);
}


void print_regex_rules() {
    printf("Regex rules:\n");
    printf("  NO   Token_id   Regex\n");
    int i;
    for (i = 0; i < NR_REGEX; i++) {
        printf("  %-5d %-10d %-4s\n", i, rules[i].token_type, rules[i].regex);
    }
}

word_t expr(char *e, bool *success) {
    if (!make_token(e)) {
        *success = false;
        return 0;
    }

    /// TODO: 表达式赋值
    TODO("expression evaluation");

    return 0;
}