void debug_hook();
void dump_e_i();
void exec_debug();

// opcode constants
#define OP_BREAK  1
#define OP_PENV   2
#define OP_PTRACE 3

#define HALT_CODE   0xffffffff

// print instructions before crash
#define CRASH_TRACE_NUM 20

