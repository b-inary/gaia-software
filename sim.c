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
#include "debug.h"
#include "fpu.h"

#define HALT_CODE   0xffffffff

#define IRQ_PSEUDO   0
#define IRQ_TIMER    1
#define IRQ_SERIAL   2
#define IRQ_SYSENTER 3

#define PGCOLOR(va)    ((va) & 0x3000)

uint32_t reg[32];
uint32_t *mem;
uint32_t mem_size = 0x400000;
uint32_t entry_point = 0x2000;
uint32_t pc;
uint32_t prog_size;
uint32_t intr_addr, intr_enabled, epc, irq_num, irq_bits;
uint32_t mmu_enabled, pd_addr;
int debug_enabled;
long long inst_cnt;
struct termios original_ttystate;

char infile[128];
int show_stat, boot_test, sim_intr_disabled, use_maswag_fpu;

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
    if (mmu_enabled) {
        fprintf(stderr, "<Current Virtual PC>: 0x%08x\n", pc);
        if (show_vpc)
            fprintf(stderr, "<Current Physical PC>: 0x%06x\n", to_physical(pc));
    } else {
        fprintf(stderr, "<Current PC>: 0x%06x\n", pc);
    }
    fprintf(stderr, "<Number of executed instructions>: %lld\n", inst_cnt);
}

void error(char *, ...) __attribute__((noreturn));
void error(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "\x1b[1;31mruntime error: \x1b[39m");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\x1b[0m\n\n");
    print_env(strncmp("to_physical: ", fmt, strlen("to_physical: ")));
    restore_term();
    dump_e_i();
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

uint32_t alu(int tag, int ra, int rb, uint32_t lit)
{
    uint32_t t = reg[rb] + lit;
    switch (tag) {
        case  0: return reg[ra] + t;
        case  1: return reg[ra] - t;
        case  2: return reg[ra] << t;
        case  3: return reg[ra] >> t;
        case  4: return (int32_t)reg[ra] >> t;
        case  5: return reg[ra] & t;
        case  6: return reg[ra] | t;
        case  7: return reg[ra] ^ t;
        case  8: return reg[ra] + 4 * t;
        case 22: return reg[ra] <  t;
        case 23: return reg[ra] <= t;
        case 24: return reg[ra] != t;
        case 25: return reg[ra] == t;
        case 26: return (int32_t)reg[ra] <  (int32_t)t;
        case 27: return (int32_t)reg[ra] <= (int32_t)t;
        // case 28: return bitfloat(reg[ra]) != bitfloat(reg[rb]);
        // case 29: return bitfloat(reg[ra]) == bitfloat(reg[rb]);
        case 30: return bitfloat(reg[ra]) <  bitfloat(reg[rb]);
        case 31: return bitfloat(reg[ra]) <= bitfloat(reg[rb]);
        default: error("instruction decode error (ALU)");
    }
}

uint32_t fpu(int tag, int ra, int rb)
{
    switch (tag) {
        case 0:  return bitint(bitfloat(reg[ra]) + bitfloat(reg[rb]));
        case 1:  return bitint(bitfloat(reg[ra]) - bitfloat(reg[rb]));
        case 2:  return bitint(bitfloat(reg[ra]) * bitfloat(reg[rb]));
        // case 3:  return bitint(bitfloat(reg[ra]) / bitfloat(reg[rb]));
        case 4:  return bitint(1.0 / bitfloat(reg[ra]));
        case 5:  return bitint(sqrtf(bitfloat(reg[ra])));
        case 6:  return (int32_t)roundf(bitfloat(reg[ra]));
        case 7:  return bitint((float)(int32_t)reg[ra]);
        case 8:  return bitint(floorf(bitfloat(reg[ra])));
        default: error("instruction decode error (FPU)");
    }
}

uint32_t fpu_maswag(int tag, int ra, int rb)
{
    switch (tag) {
        case 0:  return fadd(reg[ra], reg[rb]);
        case 1:  return fsub(reg[ra], reg[rb]);
        case 2:  return fmul(reg[ra], reg[rb]);
        // case 3:  return fdiv(reg[ra], reg[rb]);
        case 4:  return finv(reg[ra]);
        case 5:  return fsqrt(reg[ra]);
        case 6:  return h_f2i(reg[ra]);
        case 7:  return h_i2f(reg[ra]);
        case 8:  return h_floor(reg[ra]);
        default: error("instruction decode error (FPU)");
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

uint32_t care_minus_zero(uint32_t x)
{
    return x == 0x80000000 ? 0 : x;
}

// Warning: Error messages in "to_physical" MUST starts with "to_physical: " to prevent
//          infinite loop in "error" function, which may call "to_physical" again.
uint32_t to_physical(uint32_t addr)
{
    uint32_t tmp;
    if (!mmu_enabled) return addr;
    tmp = pd_addr | ((addr >> 22) << 2);
    if (tmp & 3 || tmp >= mem_size)
        error("to_physical: PDE address error: 0x%08x, Requested virtual address: 0x%08x", tmp, addr);
    tmp = mem[tmp >> 2];
    if ((tmp & 1) == 0)
        error("to_physical: invalid PDE, Requested virtual address: 0x%08x", addr);
    tmp = (tmp & ~0x0fff) | (((addr >> 12) & 0x03ff) << 2);;
    if (tmp >= mem_size)
        error("to_physical: PTE address error: 0x%08x, Requested virtual address: 0x%08x", tmp, addr);
    tmp = mem[tmp >> 2];
    if ((tmp & 1) == 0)
        error("to_physical: invalid PTE, Requested virtual address: 0x%08x", addr);
    tmp = (tmp & ~0x0fff) | (addr & 0x0fff);
    if (PGCOLOR(tmp) != PGCOLOR(addr))
        error("to_physical: invalid page color: Physical adrress: 0x%08x, Requested virtual address: 0x%08x", tmp, addr);
    return tmp;
}

int has_input()
{
    int c = getchar();
    if (c == EOF)
        return 0;
    ungetc(c, stdin);
    return 1;
}

uint32_t serial_read()
{
    return getchar();
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
    if (addr < mem_size) {
        return mem[addr >> 2];
    } else {
        switch (addr) {
            case 0x80001000: return serial_read();
            case 0x80001004: return 1; // Tx ready bit is already high in simulation
            case 0x80001100: return intr_addr;
            case 0x80001104: return intr_enabled;
            case 0x80001108: return epc;
            case 0x8000110c: return irq_num;
            case 0x80001200: return mmu_enabled;
            case 0x80001204: return pd_addr;
            default: error("load: exceeded %dMB limit: 0x%08x", mem_size >> 20, addr);
        }
    }
}

uint32_t load_byte(int ra, uint32_t disp)
{
    uint32_t addr = to_physical(reg[ra] + disp);
    if (addr >= mem_size)
        error("load_byte: exceeded %dMB limit: 0x%08x", mem_size >> 20, addr);
    return *((int8_t *)mem + addr);
}

void store(int ra, uint32_t disp, uint32_t x)
{
    uint32_t addr = to_physical(reg[ra] + (disp << 2));

    if (addr & 3)
        error("store: address must be a multiple of 4: 0x%08x", addr);
    if (addr < mem_size) {
        mem[addr >> 2] = x;
    } else {
        switch (addr) {
            case 0x80001000: serial_write(x); break;
            case 0x80001100: intr_addr = x; break;
            case 0x80001104: intr_enabled = x; break;
            case 0x80001108: epc = x; break;
            case 0x8000110c: irq_num = x; break;
            case 0x80001200: mmu_enabled = x; break;
            case 0x80001204: pd_addr = x; break;
            default: error("store: exceeded %dMB limit: 0x%08x", mem_size >> 20, addr);
        }
    }
}

void store_byte(int ra, uint32_t disp, uint32_t x)
{
    uint32_t addr = to_physical(reg[ra] + disp);
    if (addr >= mem_size)
        error("store_byte: exceeded %dMB limit: 0x%08x", mem_size >> 20, addr);
    *((uint8_t *)mem + addr) = x;
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
    uint32_t res = use_maswag_fpu ? fpu_maswag(tag, ra, rb) : fpu(tag, ra, rb);
    reg[rx] = care_minus_zero(fpu_sign(res, sign));
}

void exec_misc(uint32_t inst)
{
    int opcode = inst >> 28;
    int rx = (inst >> 23) & 31;
    int ra = (inst >> 18) & 31;
    uint32_t disp = inst & 0xffff, tmp;
    if (disp >= 0x8000) disp -= 0x10000;
    switch (opcode) {
        case 2:
            reg[rx] = disp;
            return;
        case 3:
            reg[rx] = (disp << 16) | (reg[ra] & 0xffff);
            return;
        case 4:
            reg[rx] = pc + 4;
            pc += disp << 2;
            return;
        case 5:
            if (reg[ra] & 3)
                error("jr: register corrupted: r%d", ra);
            if (to_physical(reg[ra]) >= mem_size)
                error("jr: jump destination out of range: r%d", ra);
            tmp = reg[ra];
            reg[rx] = pc + 4;
            pc = tmp - 4;
            return;
        case 6:
            reg[rx] = load(ra, disp);
            return;
        case 7:
            reg[rx] = load_byte(ra, disp);
            return;
        case 8:
            store(ra, disp, reg[rx]);
            return;
        case 9:
            store_byte(ra, disp, reg[rx]);
            return;
        case 10:
            exec_debug(rx, disp);
            return;
        case 12:
            intr_enabled = 0;
            irq_num = IRQ_SYSENTER; // IRQ number
            epc = pc + 4; // GAIA cpus store the correct interrupted address for sysenter exception.
            pc = intr_addr - 4;
            return;
        case 13:
            pc = epc - 4;
            intr_enabled = 1;
            return;
        case 14:
            if (reg[rx] != reg[ra]) pc += disp << 2;
            return;
        case 15:
            if (reg[rx] == reg[ra]) pc += disp << 2;
            return;
        default:
            error("instruction decode error");
    }
}

void exec(uint32_t inst)
{
    int opcode = inst >> 28;
    switch (opcode) {
        case  0: exec_alu(inst); break;
        case  1: exec_fpu(inst); break;
        default: exec_misc(inst); break;
    }
}

void update_irqbits()
{
    static int tick;

    // TIMER
    if (++tick >= (int)(93.33e6 / 100)) {
        irq_bits |= 1 << IRQ_TIMER;
        tick = 0;
    }

    // SERIAL
    if (has_input())
        irq_bits |= 1 << IRQ_SERIAL;
}

void interrupt()
{
    update_irqbits();
    if (irq_bits && intr_enabled) {
        intr_enabled = 0;
        epc = pc + 4; // GAIA cpus store interrupted address + 4.
        irq_num = __builtin_ctz(irq_bits); // IRQ number
        pc = intr_addr;
        irq_bits &= ~(1 << irq_num); // auto EOI
    }
}

void init_env()
{
    free(mem);
    mem = malloc(mem_size);
    if (!boot_test)
        reg[30] = reg[31] = mem_size;
    pc = entry_point;
    inst_cnt = 0;
    irq_bits = 0;
}

void init_term()
{
    struct termios ttystate;
    if (!isatty(fileno(stdin)) || sim_intr_disabled)
        return;
    tcgetattr(fileno(stdin), &ttystate);
    original_ttystate = ttystate;
    cfmakeraw(&ttystate);
    ttystate.c_lflag |= ISIG;
    ttystate.c_oflag |= OPOST;
    ttystate.c_cc[VMIN] = 0;
    ttystate.c_cc[VTIME] = 0;
    tcsetattr(fileno(stdin), TCSANOW, &ttystate);
}

void restore_term()
{
    if (!isatty(fileno(stdin)) || sim_intr_disabled)
        return;
    tcsetattr(fileno(stdin), TCSANOW, &original_ttystate);
}

void load_file()
{
    FILE *fp = fopen(infile, "r");
    if (fp == NULL)
        error(strerror(errno));

    prog_size = 0;
    for (int i = 0; i < 32; i += 8)
        prog_size += fgetc(fp) << i;

    for (uint32_t i = 0; i < prog_size; ++i) {
        int c = fgetc(fp);
        if (c == EOF)
            error("load_file: reached EOF (actual size is less than header)");
        *((uint8_t*)mem + entry_point + i) = c;
    }

    if (fgetc(fp) != EOF)
        error("load_file: input file remained (actual size is more than header)");
    fclose(fp);
}

void runsim()
{
    init_env();
    load_file();
    while (1) {
        uint32_t phys_pc;
        if (! sim_intr_disabled)
            interrupt();
        if (debug_enabled)
            debug_hook();
        phys_pc = to_physical(pc);
        if (phys_pc >= mem_size)
            error("program counter out of range");
        if (mem[phys_pc >> 2] == HALT_CODE)
            break;
        exec(mem[phys_pc >> 2]);
        pc += 4;
        ++inst_cnt;
    }
}

void print_help(char *prog)
{
    fprintf(stderr, "usage: %s [options] file\n", prog);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -boot-test        bootloader test mode\n");
    fprintf(stderr, "  -debug            enable debugging feature\n");
    fprintf(stderr, "  -fpu-maswag       use MasWag's FPU\n");
    fprintf(stderr, "  -msize <integer>  change memory size (MB)\n");
    fprintf(stderr, "  -no-interrupt     disable interrupt feature\n");
    fprintf(stderr, "  -simple           same as -no-interrupt\n");
    fprintf(stderr, "  -stat             show simulator status\n");
    exit(1);
}

void parse_cmd(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-boot-test") == 0) {
            entry_point = 0;
            boot_test = 1;
        } else if (strcmp(argv[i], "-debug") == 0) {
            debug_enabled = 1;
        } else if (strcmp(argv[i], "-fpu-maswag") == 0) {
            use_maswag_fpu = 1;
        } else if (strcmp(argv[i], "-msize") == 0) {
            if (i == argc - 1) print_help(argv[0]);
            mem_size = atoi(argv[++i]) << 20;
        } else if (strcmp(argv[i], "-no-interrupt") == 0) {
            sim_intr_disabled = 1;
        } else if (strcmp(argv[i], "-simple") == 0) {
            sim_intr_disabled = 1;
        } else if (strcmp(argv[i], "-stat") == 0) {
            show_stat = 1;
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
    if (show_stat) {
        print_env(1);
        dump_e_i();
    }
    restore_term();
    return 0;
}

