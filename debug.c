#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>
#include "debug.h"

// env
extern uint32_t reg[32];
extern uint32_t *mem;
extern uint32_t pc;
uint32_t to_physical(uint32_t);
void print_env(int show_vpc);

int debug_enabled;

// defined in sim.c
void init_term();
void restore_term();
void error(char*, ...);

// disasm
struct inst_struct{
  char opname[10];
  char rx;  char ra;  char rb;
  char literal;  char displacement;
};
void disasm(uint32_t inst, struct inst_struct *ip);

//for debug func
static int is_indebug = 0;
void print_disasm(FILE*, uint32_t);
void dump_e_i();
void update_e_i(uint32_t, uint32_t);


void exec_debug(uint32_t inst)
{
  uint32_t tag, lit;

  if (!debug_enabled)
      return;
  tag = inst & 31;
  lit = (inst >> 5) & 255;
  switch (tag) {
    case OP_BREAK:
      fprintf(stderr, "\x1b[1;31mbreak point %d:\x1b[39m\n", lit);
      print_env(1);
      is_indebug = 1;
      break;
    case OP_PENV:
      fprintf(stderr, "\x1b[1;31mprint status. id %d:\x1b[39m\n", lit);
      print_env(1);
      break;
    case OP_PTRACE:
      fprintf(stderr, "\x1b[1;31mprint trace. id %d:\x1b[39m\n", lit);
      dump_e_i();
      break;
    default:
      error("instruction decode error");
  }
}

void do_interactive_loop()
{
  char cmd[32];

  fprintf(stderr, "help: c, n, stat, trace, mem and list commands are available.\n");
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
        fprintf(stderr, "\x1b[1;31merror. mem command usage: mem 0xaddr [count]\x1b[39m\n");
      } else {
        if (argc < 2)
          count = 1;
        for (i = 0; i < count; i++)
          fprintf(stderr, "0x%08x: 0x%08x\n", addr + i * 4, mem[to_physical(addr + i * 4) >> 2]);
      }
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
    }
    else {
      fprintf(stderr, "unknown command %s\n", cmd);
    }
  }
}

void debug_hook()
{
  uint32_t phys_pc;

  if (!debug_enabled)
      return;
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

// 
// crash trace
//
uint32_t e_inst[CRASH_TRACE_NUM];
uint32_t e_inst_loc[CRASH_TRACE_NUM];

void dump_e_i(){
  int i;
  if (!debug_enabled)
      return;
  fprintf(stderr, "address | code | opname, [rx, ra, rb], [literal], [displacement]\n");
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
void print_disasm(FILE *out, uint32_t inst)
{
  struct inst_struct ip;
  disasm(inst, &ip);
  fprintf(out, "%s, [%d, %d, %d], [%d], [%d]\n",
      ip.opname,
      ip.rx, ip.ra, ip.rb,
      ip.literal,
      ip.displacement);
}

void alu_opname(int tag, struct inst_struct *ip)
{
    switch (tag) {
        case  0: strcpy(ip->opname, "add"); return;
        case  1: strcpy(ip->opname, "sub"); return;
        case  2: strcpy(ip->opname, "shl"); return;
        case  3: strcpy(ip->opname, "shr"); return;
        case  4: strcpy(ip->opname, "sar"); return;
        case  5: strcpy(ip->opname, "and"); return;
        case  6: strcpy(ip->opname, "or "); return;
        case  7: strcpy(ip->opname, "xor"); return;
        case 24: strcpy(ip->opname, "cmpne"); return;
        case 25: strcpy(ip->opname, "cmpeq"); return; 
        case 26: strcpy(ip->opname, "cmplt"); return;
        case 27: strcpy(ip->opname, "cmple"); return;
        case 28: strcpy(ip->opname, "fcmpne"); return;
        case 29: strcpy(ip->opname, "fcmpeq"); return;
        case 30: strcpy(ip->opname, "fcmplt"); return;
        case 31: strcpy(ip->opname, "fcmple"); return;
        default: strcpy(ip->opname, "ALU ERR"); return;
    }
}

void fpu_opname(int tag, struct inst_struct *ip)
{
    switch (tag) {
        case 0:  strcpy(ip->opname, "fadd"); return;
        case 1:  strcpy(ip->opname, "fsub"); return;
        case 2:  strcpy(ip->opname, "fmul"); return;
        case 3:  strcpy(ip->opname, "fdiv"); return;
        case 4:  strcpy(ip->opname, "finv"); return;
        case 5:  strcpy(ip->opname, "fsqrt"); return;
        case 6:  strcpy(ip->opname, "ftoi"); return;
        case 7:  strcpy(ip->opname, "itof"); return;
        case 8:  strcpy(ip->opname, "floor"); return;
        default: strcpy(ip->opname, "FPU ERR"); return;
    }
}

void disasm_alu(uint32_t inst, struct inst_struct *ip)
{
    int tag = inst & 31;
    uint32_t lit = (inst >> 5) & 255;
    if (lit >= 128) lit -= 256;
    ip->rx = (inst >> 23) & 31;
    ip->ra = (inst >> 18) & 31;
    ip->rb = (inst >> 13) & 31;
    ip->literal = lit;
    alu_opname(tag, ip);
}

void disasm_fpu(uint32_t inst, struct inst_struct *ip)
{
    int tag = inst & 31;
    ip->rx = (inst >> 23) & 31;
    ip->ra = (inst >> 18) & 31;
    ip->rb = (inst >> 13) & 31;
    fpu_opname(tag, ip);
}

void disasm_misc(uint32_t inst, struct inst_struct *ip)
{
    int opcode = inst >> 28;
    uint32_t disp = inst & 0xffff;
    if (disp >= 0x8000) disp -= 0x10000;
    ip->rx = (inst >> 23) & 31;
    ip->ra = (inst >> 18) & 31;
    ip->displacement = disp;

    switch (opcode) {
        case 2: strcpy(ip->opname, "ldl"); return;
        case 3: strcpy(ip->opname, "ldh"); return;
        case 4: strcpy(ip->opname, "sysenter"); return;
        case 5: strcpy(ip->opname, "sysexit");  return;
        case 6: strcpy(ip->opname, "store"); return;
        case 8: strcpy(ip->opname, "load "); return;
        case 11:strcpy(ip->opname, "jl "); return;
        case 12:strcpy(ip->opname, "jr "); return;
        case 13:strcpy(ip->opname, "bne"); return;
        case 15:strcpy(ip->opname, "beq"); return;
        default:strcpy(ip->opname, "MISCERR"); return;
    }
}

void disasm(uint32_t inst, struct inst_struct *ip)
{
    int opcode = inst >> 28;
    switch (opcode) {
        case 0:  disasm_alu(inst, ip); break;
        case 1:  disasm_fpu(inst, ip); break;
        default: disasm_misc(inst,ip); break;
    }
}


