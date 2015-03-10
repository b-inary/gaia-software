#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>
#include "debug.h"

// env
extern uint32_t reg[32];
extern uint32_t *mem;
extern uint32_t pc;
uint32_t to_physical(uint32_t);
uint32_t load(int ra, uint32_t disp);
void print_env(int show_vpc);

// Disable debugging feature if simulation speed is needed. Default: 0
extern int debug_enabled;

// defined in sim.c
void init_term();
void restore_term();
void error(char*, ...);

//for debug func
static int is_indebug = 0;
void print_disasm(FILE*, uint32_t);
void dump_e_i();
void update_e_i(uint32_t, uint32_t);
int is_break_disabled(int);
void disable_break(int);
void enable_break(int);
void disable_break_all();
void enable_break_all();

int break_disabled[8];

void exec_debug(int tag, int lit)
{
  if (!debug_enabled)
    return;

  switch (tag) {
    case OP_BREAK:
      if (is_break_disabled(lit))
        break;
      fprintf(stderr, "\x1b[1;31mbreak point %d:\x1b[0;39m\n", lit);
      print_env(1);
      is_indebug = 1;
      break;
    case OP_PENV:
      fprintf(stderr, "\x1b[1;31mprint status. id %d:\x1b[0;39m\n", lit);
      print_env(1);
      break;
    case OP_PTRACE:
      fprintf(stderr, "\x1b[1;31mprint trace. id %d:\x1b[0;39m\n", lit);
      dump_e_i();
      break;
    default:
      error("instruction decode error (debug)");
  }
}

void do_interactive_loop()
{
  char cmd[32];

  fprintf(stderr, "help: c, n, stat, trace, mem, list, disable and enable commands are available.\n");
  for (;;) {
    fprintf(stderr, "> ");
    if (fgets(cmd, sizeof(cmd), stdin) == NULL)
      break;

    if (strcmp("c\n", cmd) == 0) {
      // continue
      is_indebug = 0;
      break;
    } else if (strcmp("n\n", cmd) == 0) {
      // next
      break;
    } else if (strcmp("stat\n", cmd) == 0) {
      // print the simulation environment status
      print_env(1);
    } else if (strcmp("trace\n", cmd) == 0) {
      // print the trace of last 20 instructions
      dump_e_i();
    } else if (strncmp("mem", cmd, 3) == 0) {
      // print memory contents
      int addr, count, argc;
      int i;

      if ((argc = sscanf(cmd, "mem %x %d", &addr, &count)) < 1) {
        fprintf(stderr, "\x1b[1;31merror. mem command usage: mem 0xaddr [count]\x1b[0;39m\n");
        continue;
      }
      if (argc < 2)
        count = 1;
      for (i = 0; i < count; i++)
        fprintf(stderr, "0x%08x: 0x%08x\n", addr + i * 4, load(0, (addr + i * 4) >> 2));

    } else if (strncmp("list", cmd, 4) == 0) {
      // print the next N instructions
      int count, argc;
      int i;

      argc = sscanf(cmd, "list %d", &count);
      if (argc < 1)
        count = 10;
      for (i = 0; i < count; i++) {
        fprintf(stderr, "0x%08x: ", pc + i * 4);
        print_disasm(stderr, mem[to_physical(pc + i * 4) >> 2]);
      }

    } else if (strncmp("disable", cmd, 7) == 0) {
      // Disable Nth break point
      int num;

      if (sscanf(cmd, "disable %d", &num) >= 1) {
        fprintf(stderr, "\x1b[1;31mbreak point %d disabled.\x1b[0;39m\n", num);
        disable_break(num);
      } else if(sscanf(cmd, "disable all") != EOF) {
        fprintf(stderr, "\x1b[1;31mall break point disabled.\x1b[0;39m\n");
        disable_break_all();
      } else {
        fprintf(stderr, "\x1b[1;31merror. disable command usage: disable [break point number] OR disable all\x1b[0;39m\n");
      }

    } else if (strncmp("enable", cmd, 6) == 0) {
      // Enable Nth break point
      int num;

      if (sscanf(cmd, "enable %d", &num) >= 1) {
        fprintf(stderr, "\x1b[1;31mbreak point %d enabled.\x1b[0;39m\n", num);
        enable_break(num);
      } else if(sscanf(cmd, "enable all") != EOF) {
        fprintf(stderr, "\x1b[1;31mall break point enabled.\x1b[0;39m\n");
        enable_break_all();
      } else {
        fprintf(stderr, "\x1b[1;31merror. enable command usage: enable [break point number] OR enable all\x1b[0;39m\n");
      }

    }
    else {
      fprintf(stderr, "unknown command %s\n", cmd);
    }
  }
}

void debug_hook()
{
  uint32_t phys_pc;

  if (reg[0] != 0)
    error("r0 is not zero");

  phys_pc = to_physical(pc);
  update_e_i(pc, mem[phys_pc >> 2]);
  if (is_indebug) {
    struct termios ttystate;

    tcgetattr(fileno(stdin), &ttystate);
    restore_term();

    fprintf(stderr, "0x%08x: ", pc);
    print_disasm(stderr, mem[phys_pc >> 2]);
    do_interactive_loop();

    tcsetattr(fileno(stdin), TCSANOW, &ttystate);
  }
}

inline int is_break_disabled(int num)
{
  return break_disabled[num / 32] & (1 << (num % 32));
}

inline void disable_break(int num)
{
  break_disabled[num / 32] |= (1 << (num % 32));
}

inline void disable_break_all()
{
  for (int i = 0; i < 8; i++)
    break_disabled[i] = -1;
}

inline void enable_break(int num)
{
  break_disabled[num / 32] &= ~(1 << (num % 32));
}

inline void enable_break_all()
{
  for (int i = 0; i < 8; i++)
    break_disabled[i] = 0;
}

//
// crash trace
//
uint32_t e_inst[CRASH_TRACE_NUM];
uint32_t e_inst_loc[CRASH_TRACE_NUM];

void dump_e_i(){
  int i;
  if (!debug_enabled)
      return;
  fprintf(stderr, "  address  |    code    |      assembly\n");
  for(i=0; i<CRASH_TRACE_NUM; i++){
    fprintf(stderr, "0x%08x | 0x%08x | ", e_inst_loc[i], e_inst[i]);
    print_disasm(stderr, e_inst[i]);
  }
}
void update_e_i(uint32_t pc, uint32_t now_i){
  int i;
  for(i=CRASH_TRACE_NUM-1; i-1>=0; i--){
    e_inst[i] = e_inst[i-1];
    e_inst_loc[i] = e_inst_loc[i-1];
  }
  e_inst[0] = now_i;
  e_inst_loc[0] = pc;
}

//
// disasm
//
#define SLICE(u, i, j) (((u) << (31 - (i))) >> (31 - (i) + (j)))

void print_disasm(FILE *fp, uint32_t ins)
{
  char *regs[32] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
    "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
    "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29",
    "rsp", "rbp",
  };

  char *aop[] = {
    [ 0] = "add",     [ 1] = "sub",
    [ 2] = "shl",     [ 3] = "shr",
    [ 4] = "sar",     [ 5] = "and",
    [ 6] = "or",      [ 7] = "xor",
    [22] = "cmpult",  [23] = "cmpule",
    [24] = "cmpne",   [25] = "cmpeq",
    [26] = "cmplt",   [27] = "cmple",
    [28] = "fcmpne",  [29] = "fcmpeq",
    [30] = "fcmplt",  [31] = "fcmple",
  };

  char *fop[] = {
    [ 0] = "fadd",    [ 1] = "fsub",
    [ 2] = "fmul",    [ 3] = "fdiv",
    [ 4] = "finv",    [ 5] = "fsqrt",
    [ 6] = "ftoi",    [ 7] = "itof",
    [ 8] = "floor",
  };

  char *fsig[] = {
    [ 0] = "",
    [ 1] = ".neg",
    [ 2] = ".abs",
    [ 3] = ".abs.neg",
  };

  char *dop[] = {
    [ 1] = "break",
    [ 2] = "penv",
    [ 3] = "ptrace",
  };

  char *mop[] = {
    [ 6] = "ld",
    [ 7] = "ldb",
    [ 8] = "st",
    [ 9] = "stb",
    [12] = "sysenter",
    [13] = "sysexit",
    [14] = "bne",
    [15] = "beq",
  };

  int op, rx, ra, rb, lit, tag, sig, disp;

  op = SLICE(ins, 31, 28);
  rx = SLICE(ins, 27, 23);
  ra = SLICE(ins, 22, 18);
  rb = SLICE(ins, 17, 13);
  lit = SLICE(ins, 12, 5);
  tag = SLICE(ins, 4, 0);
  sig = SLICE(ins, 6, 5);
  disp = SLICE(ins, 15, 0);

  switch (op) {
    case 0: // ALU
      if (lit >= 128)
        lit -= 256;
      if (tag < 28)
        fprintf(fp, "%s %s, %s, %s, %d\n", aop[tag], regs[rx], regs[ra], regs[rb], lit);
      else
        fprintf(fp, "%s %s, %s, %s\n", aop[tag], regs[rx], regs[ra], regs[rb]);
      break;
    case 1: // FPU
      if (tag < 5)
        fprintf(fp, "%s%s %s, %s, %s\n", fop[tag], fsig[sig], regs[rx], regs[ra], regs[rb]);
      else
        fprintf(fp, "%s%s %s, %s\n", fop[tag], fsig[sig], regs[rx], regs[ra]);
      break;
    case 2: // ldl
      fprintf(fp, "ldl %s, %#x\n", regs[rx], disp);
      break;
    case 3: // ldh
      fprintf(fp, "ldh %s, %s, %#x\n", regs[rx], regs[ra], disp);
      break;
    case 4: // jl
      disp *= 4;
      if (disp >= 0x20000)
        disp -= 0x40000;
      fprintf(fp, "jl %s, %s%#x\n", regs[rx], disp < 0 ? "-" : "", abs(disp));
      break;
    case 5: // jr
      fprintf(fp, "jr %s, %s\n", regs[rx], regs[ra]);
      break;
    case 6: case 8: case 14: case 15: // ld, st, bne, beq
      disp *= 4;
      if (disp >= 0x20000)
        disp -= 0x40000;
      fprintf(fp, "%s %s, %s, %s%#x\n", mop[op], regs[rx], regs[ra], disp < 0 ? "-" : "", abs(disp));
      break;
    case 7: case 9: // ldb, stb
      if (disp >= 0x8000)
        disp -= 0x10000;
      fprintf(fp, "%s %s, %s, %s%#x\n", mop[op], regs[rx], regs[ra], disp < 0 ? "-" : "", abs(disp));
      break;
    case 10: // debug
      fprintf(fp, "%s %d\n", dop[rx], disp);
      break;
    case 12: case 13: // sysenter, sysexit
      fprintf(fp, "%s\n", mop[op]);
      break;
  }
}
