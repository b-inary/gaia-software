#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#define HALT_CODE   0xffffffff

#define IRQ_PSEUDO   0
#define IRQ_TIMER    1
#define IRQ_SERIAL   2
#define IRQ_SYSENTER 3

uint32_t reg[32];
uint32_t *mem;
uint32_t mem_size = 0x400000;
uint32_t entry_point = 0x3000;
uint32_t pc;
uint32_t prog_size;
uint32_t irq_bits;
long long inst_cnt;
struct termios original_ttystate;

char infile[128];
int show_stat, boot_test, mmu_enabled = 1, interrupt_enabled = 1;

uint32_t to_physical(uint32_t);
void restore_term();

void print_env(int show_vpc)
{
    fprintf(stderr, "\x1b[1m*** Simulator Status ***\x1b[0m\n");
    if (show_stat) {
        fprintf(stderr, "<register>\n");
        for (int i = 0; i < 16; ++i)
            fprintf(stderr, "  r%-2d: %11d (0x%08x) / r%-2d: %11d (0x%08x)\n",
                    i, reg[i], reg[i], i + 16, reg[i + 16], reg[i + 16]);
    }
    if (show_vpc)
        fprintf(stderr, "<Current Virtual PC>: 0x%08x, <Current Physical PC>: 0x%06x\n", pc, to_physical(pc));
    else
        fprintf(stderr, "<Current PC>: 0x%08x\n", pc);
    fprintf(stderr, "<Number of executed instructions>: %lld\n", inst_cnt);
}

void error(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "\x1b[1;31mruntime error: \x1b[39m");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\x1b[0m\n\n");
    print_env(!strcmp("to_physical: ", fmt));
    restore_term();
    va_end(ap);
    exit(1);
}

uint32_t bitint(float x)
{
    union { uint32_t i; float f; } u;
    u.f = x;
    return u.i;
}

float bitfloat(uint32_t x)
{
    union { uint32_t i; float f; } u;
    u.i = x;
    return u.f;
}

// Find the last bit set in a word, the opposite of ffs.
int fls(uint32_t i)
{
    if (i == 0) return 0;
    int res = 0;
    while ((i & (1 << res)) == 0) res++;
    return res + 1;
}

uint32_t alu(int tag, int ra, int rb, uint32_t lit)
{
    switch (tag) {
        case  0: return reg[ra] + reg[rb] + lit;
        case  1: return reg[ra] - reg[rb] - lit;
        case  2: return reg[ra] << (reg[rb] + lit);
        case  3: return reg[ra] >> (reg[rb] + lit);
        case  4: return (int32_t)reg[ra] >> (reg[rb] + lit);
        case  5: return reg[ra] & reg[rb] & lit;
        case  6: return reg[ra] | reg[rb] | lit;
        case  7: return reg[ra] ^ reg[rb] ^ lit;
        case 24: return reg[ra] != reg[rb] + lit;
        case 25: return reg[ra] == reg[rb] + lit;
        case 26: return (int32_t)reg[ra] <  (int32_t)(reg[rb] + lit);
        case 27: return (int32_t)reg[ra] <= (int32_t)(reg[rb] + lit);
        case 28: return bitfloat(reg[ra]) != bitfloat(reg[rb]);
        case 29: return bitfloat(reg[ra]) == bitfloat(reg[rb]);
        case 30: return bitfloat(reg[ra]) <  bitfloat(reg[rb]);
        case 31: return bitfloat(reg[ra]) <= bitfloat(reg[rb]);
        default: error("instruction decode error (ALU)"); return 0;
    }
}

uint32_t fpu(int tag, int ra, int rb)
{
    switch (tag) {
        case 0:  return bitint(bitfloat(reg[ra]) + bitfloat(reg[rb]));
        case 1:  return bitint(bitfloat(reg[ra]) - bitfloat(reg[rb]));
        case 2:  return bitint(bitfloat(reg[ra]) * bitfloat(reg[rb]));
        case 3:  return bitint(bitfloat(reg[ra]) / bitfloat(reg[rb]));
        case 4:  return bitint(1.0 / bitfloat(reg[ra]));
        case 5:  return bitint(sqrtf(bitfloat(reg[ra])));
        case 6:  return (uint32_t)roundf(bitfloat(reg[ra]));
        case 7:  return bitint((float)reg[ra]);
        case 8:  return bitint(floorf(bitfloat(reg[ra])));
        default: error("instruction decode error (FPU)"); return 0;
    }
}

uint32_t fpu_sign(uint32_t x, int mode)
{
    switch (mode) {
        case 1:  return x ^ 0x80000000;
        case 2:  return x & 0x7fffffff;
        case 3:  return x | 0x80000000;
        default: return x;
    }
}

// Warning: Error messages in "to_physical" MUST starts with "to_physical: " to prevent
//          infinite loop in "error" function, which may call "to_physical" again.
uint32_t to_physical(uint32_t addr)
{
    uint32_t tmp;
    if (mem[0x2200 >> 2] == 0 || !mmu_enabled) return addr;
    tmp = mem[0x2204 >> 2] | ((addr >> 22) << 2);
    if (tmp & 3 || tmp >= mem_size)
        error("to_physical: PDE address error: 0x%08x", tmp);
    tmp = mem[tmp >> 2];
    if ((tmp & 1) == 0)
        error("to_physical: invalid PDE");
    tmp = (tmp & ~0x0fff) | (((addr >> 12) & 0x03ff) << 2);;
    if (tmp >= mem_size)
        error("to_physical: PTE address error: 0x%08x", tmp);
    tmp = mem[tmp >> 2];
    if ((tmp & 1) == 0)
        error("to_physical: invalid PTE");
    return (tmp & ~0x0fff) | (addr & 0x0fff);
}

int has_input()
{
    struct timeval zero = {0, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fileno(stdin), &fds);
    return select(fileno(stdin) + 1, &fds, NULL, NULL, &zero);
}

uint32_t serial_read()
{
    int res;
    if (has_input()) {
        res = getchar();
        if (res == EOF) error("read: reached EOF");
    } else {
        res = (uint32_t) -1;
    }
    return res;
}

void serial_write(uint32_t x)
{
    putchar(x);
    fflush(stdout);
}

uint32_t load(int ra, uint32_t disp)
{
    uint32_t addr = to_physical(reg[ra] + (disp << 2));
    if (addr & 3)
        error("load: address must be a multiple of 4: 0x%08x", addr);
    if (addr >= mem_size)
        error("load: exceed %dMB limit: 0x%08x", mem_size >> 20, addr);
    if (addr == 0x2000)
        return serial_read();
    else
        return mem[addr >> 2];
}

void store(int ra, uint32_t disp, uint32_t x)
{
    uint32_t addr = to_physical(reg[ra] + (disp << 2));
    if (addr & 3)
        error("store: address must be a multiple of 4: 0x%08x", addr);
    if (addr >= mem_size)
        error("store: exceed %dMB limit: 0x%08x", mem_size >> 20, addr);
    if (addr == 0x2000) serial_write(x);
    else mem[addr >> 2] = x;
}

void exec_alu(uint32_t inst)
{
    int tag = inst & 31;
    int rx = (inst >> 23) & 31;
    int ra = (inst >> 18) & 31;
    int rb = (inst >> 13) & 31;
    uint32_t lit = (inst >> 5) & 255;
    if (lit >= 128) lit -= 256;
    reg[rx] = alu(tag, ra, rb, lit);
}

void exec_fpu(uint32_t inst)
{
    int tag = inst & 31;
    int rx = (inst >> 23) & 31;
    int ra = (inst >> 18) & 31;
    int rb = (inst >> 13) & 31;
    int sign = (inst >> 5) & 3;
    reg[rx] = fpu_sign(fpu(tag, ra, rb), sign);
}

void exec_misc(uint32_t inst)
{
    int opcode = inst >> 28;
    int rx = (inst >> 23) & 31;
    int ra = (inst >> 18) & 31;
    uint32_t disp = inst & 0xffff;
    if (disp >= 0x8000) disp -= 0x10000;
    switch (opcode) {
        case 2:
            reg[rx] = disp;
            return;
        case 3:
            reg[rx] = (disp << 16) | (reg[ra] & 0xffff);
            return;
        case 4:
            irq_bits |= 1 << IRQ_SYSENTER;
            return;
        case 5:
            pc = mem[0x2108 >> 2];
            mem[0x2104 >> 2] = 1;
            if (mem[0x210c >> 2] != IRQ_PSEUDO) // Cause of interrupt
                irq_bits &= ~(1 << mem[0x210c >> 2]);
            return;
        case 6:
            store(ra, disp, reg[rx]);
            return;
        case 8:
            reg[rx] = load(ra, disp);
            return;
        case 11:
            reg[rx] = pc + 4;
            pc += disp << 2;
            return;
        case 12:
            if (reg[rx] & 3)
                error("jr: register corrupted: r%d", rx);
            if (to_physical(reg[rx]) >= entry_point + prog_size && !boot_test)
                error("jr: jump destination out of range: r%d", rx);
            pc = reg[rx] - 4;
            return;
        case 13:
            if (reg[rx] != reg[ra]) pc += disp << 2;
            return;
        case 15:
            if (reg[rx] == reg[ra]) pc += disp << 2;
            return;
        default:
            error("instruction decode error");
            return;
    }
}

void exec(uint32_t inst)
{
    int opcode = inst >> 28;
    switch (opcode) {
        case 0:  exec_alu(inst); break;
        case 1:  exec_fpu(inst); break;
        default: exec_misc(inst); break;
    }
}

void update_irqbits()
{
    static struct timeval tick;
    struct timeval now;

    // TIMER
    gettimeofday(&now, NULL);
    if ((now.tv_sec - tick.tv_sec) * 1000000 + now.tv_usec - tick.tv_usec > 1000000 / 100) {
        irq_bits |= 1 << IRQ_TIMER;
        gettimeofday(&tick, NULL);
    }

    // SERIAL
    if (has_input())
        irq_bits |= 1 << IRQ_SERIAL;
}

void interrupt()
{
    if (!interrupt_enabled)
        return;
    update_irqbits();
    if (irq_bits && mem[0x2104 >> 2]) {
        mem[0x210c >> 2] = fls(irq_bits) - 1; // IRQ number
        mem[0x2108 >> 2] = pc;
        mem[0x2104 >> 2] = 0;
        pc = mem[0x2100 >> 2] - 4;
    }
}

void init_env()
{
    free(mem);
    mem = malloc(mem_size);
    if (!boot_test)
        reg[30] = reg[31] = mem_size;
    pc = entry_point;
    prog_size = 0;
    inst_cnt = 0;
    irq_bits = 0;
}

void init_term()
{
    struct termios ttystate;
    if (!isatty(fileno(stdin)) || !interrupt_enabled)
        return;
    tcgetattr(fileno(stdin), &ttystate);
    original_ttystate = ttystate;
    cfmakeraw(&ttystate);
    tcsetattr(fileno(stdin), TCSANOW, &ttystate);
}

void restore_term()
{
    if (!isatty(fileno(stdin)) || !interrupt_enabled)
        return;
    tcsetattr(fileno(stdin), TCSANOW, &original_ttystate);
}

void load_file()
{
    int inst;
    FILE *fp = fopen(infile, "r");
    if (fp == NULL)
        error(strerror(errno));
    while (1) {
        inst = fgetc(fp);
        if (inst == EOF) return;
        for (int j = 1; j < 4; ++j)
            inst <<= 8, inst += fgetc(fp);
        mem[(entry_point + prog_size) >> 2] = inst;
        prog_size += 4;
    }
    fclose(fp);
}

void runsim()
{
    init_env();
    load_file();
    while (1) {
        if (to_physical(pc) >= entry_point + prog_size)
            error("program counter out of range");
        if (mem[to_physical(pc) >> 2] == HALT_CODE) break;
        exec(mem[to_physical(pc) >> 2]);
        interrupt();
        pc += 4;
        ++inst_cnt;
    }
}

void print_help(char *prog)
{
    fprintf(stderr, "usage: %s [options] file\n", prog);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -boot-test        bootloader test mode\n");
    fprintf(stderr, "  -msize <integer>  change memory size (MB)\n");
    fprintf(stderr, "  -stat             show simulator status\n");
    fprintf(stderr, "  -no-mmu           disable MMU feature\n");
    fprintf(stderr, "  -no-interrupt     disable interrupt feature\n");
    exit(1);
}

void parse_cmd(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-boot-test") == 0) {
            entry_point = 0;
            boot_test = 1;
        } else if (strcmp(argv[i], "-msize") == 0) {
            if (i == argc - 1) print_help(argv[0]);
            mem_size = atoi(argv[++i]) << 20;
        } else if (strcmp(argv[i], "-stat") == 0) {
            show_stat = 1;
        } else if (strcmp(argv[i], "-no-mmu") == 0) {
            mmu_enabled = 0;
        } else if (strcmp(argv[i], "-no-interrupt") == 0) {
            interrupt_enabled = 0;
        } else if (infile[0] != '\0') {
            fprintf(stderr, "error: multiple input files are specified\n");
            print_help(argv[0]);
        } else {
            strcpy(infile, argv[i]);
        }
    }
}

int main(int argc, char *argv[])
{
    parse_cmd(argc, argv);
    if (infile[0] == '\0') print_help(argv[0]);
    init_term();
    runsim();
    if (show_stat) print_env(1);
    restore_term();
    return 0;
}

