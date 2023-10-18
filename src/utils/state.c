/**
 * @brief Hybitor状态控制
 * @file src/utiles/state.c
 * @author lancerstadium
 * @date 2023-10-18
*/


#include "utils.h"
#include "cpu/cpu.h"

// ============================================================================ //
// state API 实现：hybitor状态控制 --> 定义 include/utils.c
// ============================================================================ //

/// @brief Hybitor状态（初始：停止）
HybitorState hybitor_state = {
    .state = HY_STOP,
};

void print_hybitor_state() {
    switch (hybitor_state.state) {
    case HY_STOP: printf("Hybitor State: " ANSI_FMT("STOP\n", ANSI_FG_YELLOW)); return;
    case HY_RUNNING: printf("Hybitor State: " ANSI_FMT("RUNNING\n", ANSI_FG_GREEN)); return;
    case HY_ABORT: printf("Hybitor State: " ANSI_FMT("ABORT\n", ANSI_FG_RED)); return;
    case HY_END: printf("Hybitor State: " ANSI_FMT("END\n", ANSI_FG_BLUE)); return;
    default: printf("Hybitor State: " ANSI_FMT("Unknown\n", ANSI_FG_CYAN)); return;
    }
}

void check_hybitor_quit_state() {
    // 检查 hybitor 状态
    switch (hybitor_state.state) {
        case HY_STOP: break;
        case HY_RUNNING: hybitor_state.state = HY_STOP; break;
        case HY_END:
            Logg("hybitor: %s at pc = " FMT_WORD, 
            (hybitor_state.halt_ret == 0 ? ANSI_FMT("GOOD TRAP", ANSI_FG_GREEN) : ANSI_FMT("BAD TARP", ANSI_FG_RED)), 
            hybitor_state.halt_pc);
            return;
        case HY_ABORT:
            Logy("hybitor: %s at pc = " FMT_WORD, 
            ANSI_FMT("ABORT", ANSI_FG_RED), 
            hybitor_state.halt_pc);
            return;
        case HY_QUIT: 
            cpu_quit();
            return;
    }
}

int is_exit_status_bad() {
    int good = (hybitor_state.state == HY_END && hybitor_state.halt_ret == 0) ||
               (hybitor_state.state == HY_QUIT);
    return !good;
}