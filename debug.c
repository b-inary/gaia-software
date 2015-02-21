#include <stdio.h>
#include <stdint.h>
#include <string.h>

// print instructions before crash
#define CRASH_TRACE_NUM 20

// env
extern uint32_t reg[32];
extern uint32_t *mem;
extern uint32_t pc;
uint32_t to_physical(uint32_t);

// disasm
struct inst_struct{
  char opname[10];
  char rx;  char ra;  char rb;
  char literal;  char displacement;
};
void disasm(uint32_t inst, struct inst_struct *ip);

//for debug func
void dump_e_i();
void update_e_i(uint32_t);

//
// debug settings
// 
int debug_condition(){
  if(reg[0] != 0) return 1;
  if(mem[phys_pc >> 2] == HALT_CODE) return 2;

  return 0;
}

void debug_routine(){
  uint32_t phys_pc;
  phys_pc = to_physical(pc);
  update_e_i(mem[phys_pc >> 2]);
}

int debug(){
  int cond;
  cond = debug_condition();

  debug_routine();

  switch(cond){
  case 1:
    fprintf(stderr, "[DEBUG]: reg[0] != 0\n");
    dump_e_i();
    return 1;
  case 2: 
    fprintf(stderr, "[DEBUG]: halt\n");
    dump_e_i();
    return 1;
  }
  return 0;
}

// 
// crash trace
//
uint32_t e_inst[CRASH_TRACE_NUM];

void dump_e_i(){
  int i;
  struct inst_struct ip;
  fprintf(stderr, "code | opname, [rx, ra, rb], [literal], [displacement]\n");
  for(i=0; i<CRASH_TRACE_NUM; i++){
    fprintf(stderr, "%x ", e_inst[i]);
    disasm(e_inst[i], &ip);
    fprintf(stderr, "%s, [%d, %d, %d], [%d], [%d]\n", 
        ip.opname, 
        ip.rx, ip.ra, ip.rb,
        ip.literal,
        ip.displacement);
  }
}
void update_e_i(uint32_t now_i){
  int i;
  for(i=CRASH_TRACE_NUM-1; i-1>=0; i--){
    e_inst[i] = e_inst[i-1];
  }
  e_inst[0] = now_i;
}

//
// disasm
//
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


