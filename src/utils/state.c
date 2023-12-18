/**
 * @brief Hybitor状态控制
 * @file src/utiles/state.c
 * @author lancerstadium
 * @date 2023-10-18
*/


#include "utils.h"
#include "emulator/cpu/cpu.h"

// ============================================================================ //
// state 宏定义
// ============================================================================ //

#define STATE_HY_STOP ANSI_FMT("STOP", ANSI_FG_YELLOW)
#define STATE_HY_RUNNING ANSI_FMT("RUNNING", ANSI_FG_GREEN)
#define STATE_HY_ABORT ANSI_FMT("ABORT", ANSI_FG_RED)
#define STATE_HY_END ANSI_FMT("END", ANSI_FG_BLUE)
#define STATE_HY_QUIT ANSI_FMT("QUIT", ANSI_FG_MAGENTA)
#define STATE_HY_UNKNOWN ANSI_FMT("Unknown", ANSI_FG_CYAN)

/// @brief Hybitor状态打印
#define PRINT_HY_STATE(state_type) \
    printf("Hybitor State: " STATE_##state_type "\n");

/// @brief Hybitor打印状态转化
/// @param src_state 源状态：`hybitor_state.state`值
/// @param des_state 目标状态
#define PRINT_TRANS_HY_STATE(src_state, des_state) \
    printf("Hybitor State: " STATE_##src_state " →  " STATE_##des_state "\n"); hybitor_state.state = des_state; 

/// @brief Hybitor设置状态转化
#define SET_HY_STATE(state_type) \
    switch (hybitor_state.state) { \
    case HY_STOP: PRINT_TRANS_HY_STATE(HY_STOP, state_type); hybitor_state.state = state_type; break; \
    case HY_RUNNING: PRINT_TRANS_HY_STATE(HY_RUNNING, state_type); hybitor_state.state = state_type; break; \
    case HY_END: PRINT_TRANS_HY_STATE(HY_END, state_type); hybitor_state.state = state_type; break; \
    case HY_ABORT: PRINT_TRANS_HY_STATE(HY_ABORT, state_type); hybitor_state.state = state_type; break; \
    case HY_QUIT: PRINT_TRANS_HY_STATE(HY_QUIT, state_type); hybitor_state.state = state_type; break; \
    default: PRINT_TRANS_HY_STATE(HY_UNKNOWN, state_type); hybitor_state.state = state_type; break; \
    }
    


// ============================================================================ //
// state API 实现：hybitor状态控制 --> 声明 include/utils.c
// ============================================================================ //

/// @brief Hybitor状态（初始：停止）
HybitorState hybitor_state = {
    .state = HY_STOP,
};

void print_hybitor_state() {
    switch (hybitor_state.state) {
    case HY_STOP: PRINT_HY_STATE(HY_STOP); return;
    case HY_RUNNING: PRINT_HY_STATE(HY_RUNNING); return;
    case HY_END: PRINT_HY_STATE(HY_END); return;
    case HY_ABORT: PRINT_HY_STATE(HY_ABORT); return;
    case HY_QUIT: PRINT_HY_STATE(HY_QUIT); return;
    default: PRINT_HY_STATE(HY_UNKNOWN); return;
    }
}

void change_hybitor_state(enum Hy_Statement state_type) {
    switch (state_type) {
    case HY_QUIT: SET_HY_STATE(HY_QUIT); return;
    case HY_ABORT: SET_HY_STATE(HY_ABORT); return;
    case HY_END: SET_HY_STATE(HY_END); return;
    case HY_RUNNING: SET_HY_STATE(HY_RUNNING); return;
    case HY_STOP: SET_HY_STATE(HY_STOP); return;
    default: SET_HY_STATE(HY_UNKNOWN); return;
    }
}

void set_hybitor_state(int state, vaddr_t pc, int halt_ret) {
    change_hybitor_state(state);
    hybitor_state.halt_pc = pc;
    hybitor_state.halt_ret = halt_ret;
}

void check_hybitor_quit_state() {
    // 检查 hybitor 状态
    switch (hybitor_state.state) {
        case HY_STOP: break;
        case HY_RUNNING: change_hybitor_state(HY_STOP); break;
        case HY_END:
            Logg("hybitor: %s at pc = " FMT_WORD, 
            (hybitor_state.halt_ret == 0 ? ANSI_FMT("GOOD TRAP", ANSI_FG_CYAN) : ANSI_FMT("BAD TARP", ANSI_FG_RED)), 
            (unsigned long int)hybitor_state.halt_pc);
            return;
        case HY_ABORT:
            Logy("hybitor: %s at pc = " FMT_WORD, 
            ANSI_FMT("ABORT", ANSI_FG_RED), 
            (unsigned long int)hybitor_state.halt_pc);
            return;
        case HY_QUIT: 
            cpu_quit();
            return;
        case HY_UNKNOWN: change_hybitor_state(HY_STOP); break;
    }
}

int is_exit_status_bad() {
    int good = (hybitor_state.state == HY_END && hybitor_state.halt_ret == 0) ||
               (hybitor_state.state == HY_QUIT);
    return !good;
}




