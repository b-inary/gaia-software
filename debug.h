void debug_hook();
void dump_e_i();
void exec_debug(int, int);

// opcode constants
#define OP_BREAK  1
#define OP_PENV   2
#define OP_PTRACE 3

// print instructions before crash
#define CRASH_TRACE_NUM 20

