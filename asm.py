#!/usr/bin/env python2.7

import sys
import os.path
import re
import struct
import argparse


srcs = {'_main': {0: 'br main'}}
filename = ''
pos = 0

def error(msg):
    print >> sys.stderr, '{}:{}: error:'.format(filename, pos), msg
    print >> sys.stderr, '  ' + srcs[filename][pos]
    sys.exit(1)


# ----------------------------------------------------------------------
#       utility functions (mainly parsing)
# ----------------------------------------------------------------------

regs = {'rsp': 30, 'rbp': 31}
for i in range(32):
    regs['r' + str(i)] = i

def is_reg(operand):
    return operand in regs

def parse_imm(operand):
    try:
        imm = int(operand, 0)
        return True, imm
    except ValueError:
        return False, 0

def parse_float(operand):
    try:
        f = float(operand)
        return True, f
    except ValueError:
        return False, 0.0

def check_imm_range(imm, b):
    x = 1 << (b - 1)
    return -x <= imm < x

def float_to_bit(f):
    try:
        s = struct.pack('>f', f)
        return struct.unpack('>i', s)[0]
    except OverflowError:
        error('floating point value is too large')

def parse_memaccess(operand):
    m = re.match(r'\[(r\w+)\s*([+-])\s*(\w+)\]$', operand)
    if m:
        base = m.group(1)
        disp = m.group(2) + m.group(3)
        if is_reg(base) and parse_imm(disp)[0]:
            return True, base, int(disp, 0)
    m = re.match(r'\[(r\w+)\]$', operand)
    if m and is_reg(m.group(1)):
        return True, m.group(1), 0
    m = re.match(r'\[([+-]?\w+)\]$', operand)
    if m and parse_imm(m.group(1))[0]:
        return True, 'r0', int(m.group(1), 0)
    return False, 'r0', 0

def check_operands_n(operands, n, m=-1):
    l = len(operands)
    if l < n:
        error('expected {} operands, but {} given'.format(n, l))
    if l > max(n, m):
        error('expected {} operands, but {} given'.format(max(n, m), l))

def regnum(reg):
    if reg not in regs:
        error('expected register: ' + reg)
    return regs[reg]

def code_i(rx, ra, rb, imm, tag):
    x = regnum(rx)
    a = regnum(ra)
    b = regnum(rb)
    success, i = parse_imm(imm)
    if not success:
        error('expected integer literal: ' + imm)
    if not check_imm_range(i, 8):
        error('immediate value (' + imm + ') is too large')
    c1 = x >> 1
    c2 = ((x & 1) << 7) + (a << 2) + (b >> 3)
    c3 = ((b & 7) << 5) + ((i >> 3) & 31)
    c4 = ((i & 7) << 5) + tag
    return chr(c1) + chr(c2) + chr(c3) + chr(c4)

def code_f(rx, ra, rb, sign, tag):
    x = regnum(rx)
    a = regnum(ra)
    b = regnum(rb)
    c1 = (1 << 4) + (x >> 1)
    c2 = ((x & 1) << 7) + (a << 2) + (b >> 3)
    c3 = ((b & 7) << 5)
    c4 = (sign << 5) + tag
    return chr(c1) + chr(c2) + chr(c3) + chr(c4)

def code_m(op, rx, ra, pred, disp, disp_mode):
    x = regnum(rx)
    a = regnum(ra)
    success, d = parse_imm(disp)
    if not success:
        error('expected displacement: ' + disp)
    if disp_mode:
        if d & 3 != 0:
            error('displacement (' + disp + ') is not a multiple of 4')
        if not check_imm_range(d, 18):
            error('displacement (' + disp + ') is too large')
        d >>= 2
    else:
        if not -0x8000 <= d <= 0xffff:
            error('immediate value (' + imm + ') is too large')
    c1 = (op << 4) + (x >> 1)
    c2 = ((x & 1) << 7) + (a << 2) + pred
    c3 = (d >> 8) & 255
    c4 = d & 255
    return chr(c1) + chr(c2) + chr(c3) + chr(c4)

def parse(line):
    line = line.strip()
    m = re.match(r'\S+', line)
    mnemonic = m.group()
    t = line[m.end():].strip()
    operands = re.split(r',\s*', t)
    if operands == ['']:
        return mnemonic, []
    return mnemonic,  operands


# ----------------------------------------------------------------------
#       mnemonic definitions
# ----------------------------------------------------------------------

def on_alu3(operands, tag):
    check_operands_n(operands, 3)
    return code_i(operands[0], operands[1], operands[2], '0', tag)

def on_alu4(operands, tag):
    check_operands_n(operands, 4)
    return code_i(operands[0], operands[1], operands[2], operands[3], tag)

def on_fpu2(operands, sign, tag):
    check_operands_n(operands, 2)
    return code_f(operands[0], operands[1], 'r0', sign, tag)

def on_fpu3(operands, sign, tag):
    check_operands_n(operands, 3)
    return code_f(operands[0], operands[1], operands[2], sign, tag)

# def on_other0(operands, op, pred):
#     check_operands_n(operands, 2)
#     return code_m(op, 'r0', 'r0', pred, '0')

def on_other1(operands, op, pred, disp_mode):
    check_operands_n(operands, 1)
    return code_m(op, operands[0], 'r0', pred, '0', disp_mode)

def on_other2(operands, op, pred, disp_mode):
    check_operands_n(operands, 2)
    return code_m(op, operands[0], 'r0', pred, operands[1], disp_mode)

def on_other3(operands, op, pred, disp_mode):
    check_operands_n(operands, 3)
    return code_m(op, operands[0], operands[1], pred, operands[2], disp_mode)

def on_dot_int(operand):
    success, imm = parse_imm(operand)
    if not success:
        error('expected integer literal: ' + operand)
    if not -0x80000000 <= imm <= 0xffffffff:
        error('immediate value (' + operand + ') is too large')
    return chr(imm >> 24 & 255) + chr(imm >> 16 & 255) + chr(imm >> 8 & 255) + chr(imm & 255)

def on_dot_float(operand):
    success, imm = parse_float(operand)
    if not success:
        error('expected floating point literal: ' + operand)
    return on_dot_int(str(float_to_bit(imm)))

alu3_table = {
    'fcmpne':   28,
    'fcmpeq':   29,
    'fcmplt':   30,
    'fcmple':   31,
}

alu4_table = {
    'add':       0,
    'sub':       1,
    'shl':       2,
    'shr':       3,
    'sar':       4,
    'and':       5,
    'or':        6,
    'xor':       7,
    'cmpne':    24,
    'cmpeq':    25,
    'cmplt':    26,
    'cmple':    27,
}

fpu2_table = {
    'finv':      4,
    'fsqrt':     5,
    'ftoi':      6,
    'itof':      7,
    'floor':     8,
}

fpu3_table = {
    'fadd':      0,
    'fsub':      1,
    'fmul':      2,
    'fdiv':      3,
}

# other0_table = {
#     'sysenter':  4,
#     'sysexit':   5,
# }

other1_table = {
    'jr':       12,
}

other2_table = {
    'ldl':       2,
    'jl':       11,
}

other3_table = {
    'ldh':       3,
    'st':        6,
    'ld':        8,
    'bne':      13,
    'beq':      15,
}

sign_table = {
    '':          0,
    'neg':       1,
    'abs':       2,
    'abs.neg':   3,
}

def code(mnemonic, operands):
    if mnemonic in alu3_table:
        return on_alu3(operands, alu3_table[mnemonic])
    if mnemonic in alu4_table:
        return on_alu4(operands, alu4_table[mnemonic])
    fpu_mnemonic, fpu_suffix = mnemonic, ''
    if '.' in mnemonic:
        fpu_mnemonic, fpu_suffix = mnemonic.split('.', 1)
    if fpu_mnemonic in fpu2_table:
        return on_fpu2(operands, sign_table[fpu_suffix], fpu2_table[fpu_mnemonic])
    if fpu_mnemonic in fpu3_table:
        return on_fpu3(operands, sign_table[fpu_suffix], fpu3_table[fpu_mnemonic])
    pred = 3 if mnemonic in ['jl', 'jr', 'bne+', 'beq+'] else 0
    disp_mode = False if mnemonic in ['ldl', 'ldh'] else True
    if mnemonic in ['bne-', 'bne+']:
        mnemonic = 'bne'
    if mnemonic in ['beq-', 'beq+']:
        mnemonic = 'beq'
    # if mnemonic in other0_table:
    #     return on_other0(operands, other0_table[mnemonic], pred, disp_mode)
    if mnemonic in other1_table:
        return on_other1(operands, other1_table[mnemonic], pred, disp_mode)
    if mnemonic in other2_table:
        return on_other2(operands, other2_table[mnemonic], pred, disp_mode)
    if mnemonic in other3_table:
        return on_other3(operands, other3_table[mnemonic], pred, disp_mode)
    if mnemonic == '.int':
        return on_dot_int(operands[0])
    if mnemonic == '.float':
        return on_dot_float(operands[0])
    error('unknown mnemonic: ' + mnemonic)


# ----------------------------------------------------------------------
#       macro definitions
# ----------------------------------------------------------------------

def expand_nop(operands):
    check_operands_n(operands, 0)
    return ['add r0, r0, r0, 0']

def mov_imm(dest, imm):
    if check_imm_range(imm, 16):
        return ['ldl {}, {}'.format(dest, imm)]
    if imm & 0xffff == 0:
        return ['ldh {}, r0, {}'.format(dest, (imm >> 16) & 0xffff)]
    return ['ldl {}, {}'.format(dest, imm & 0xffff),
            'ldh {0}, {0}, {1}'.format(dest, (imm >> 16) & 0xffff)]

def expand_mov(operands):
    check_operands_n(operands, 2)
    if is_reg(operands[0]) and is_reg(operands[1]):
        return ['add {}, {}, r0, 0'.format(operands[0], operands[1])]
    success, imm = parse_imm(operands[1])
    if success:
        return mov_imm(operands[0], imm)
    success, imm = parse_float(operands[1])
    if success:
        return mov_imm(operands[0], float_to_bit(imm))
    success, base, disp = parse_memaccess(operands[1])
    if success:
        return ['ld {}, {}, {}'.format(operands[0], base, disp)]
    success, base, disp = parse_memaccess(operands[0])
    if success:
        return ['st {}, {}, {}'.format(operands[1], base, disp)]
    m = re.match(r'\[(.+)\]$', operands[1])
    if m:
        return ['ld {}, r0, {}'.format(operands[0], m.group(1))]
    m = re.match(r'\[(.+)\]$', operands[0])
    if m:
        return ['st {}, r0, {}'.format(operands[1], m.group(1))]
    if is_reg(operands[0]):
        return ['__movl {}'.format(', '.join(operands))]
    error('invalid syntax')

# and, sub, shl, shr, sar, or, xor, cmpne, cmpeq, cmplt, cmple
def expand_alu(op, operands):
    check_operands_n(operands, 3, 4)
    if (len(operands) == 4):
        return ['{} {}'.format(op, ', '.join(operands))]
    if is_reg(operands[2]):
        return ['{} {}, 0'.format(op, ', '.join(operands))]
    success, imm = parse_imm(operands[2])
    if success:
        if check_imm_range(imm, 8):
            return ['{} {}, {}, r0, {}'.format(op, operands[0], operands[1], imm)]
        return mov_imm('r29', imm) + ['{} {}, {}, r29, 0'.format(op, operands[0], operands[1])]
    error('invalid syntax')

def expand_and(operands):
    check_operands_n(operands, 3, 4)
    if (len(operands) == 4):
        return ['and {}'.format(', '.join(operands))]
    if is_reg(operands[2]):
        return ['and {}, -1'.format(', '.join(operands))]
    success, imm = parse_imm(operands[2])
    if success:
        if check_imm_range(imm, 8):
            return ['and {0}, {1}, {1}, {2}'.format(operands[0], operands[1], imm)]
        return mov_imm('r29', imm) + ['and {}, {}, r29, -1'.format(operands[0], operands[1])]
    error('invalid syntax')

def expand_neg(operands):
    check_operands_n(operands, 2)
    return ['sub {}, r0, {}, 0'.format(operands[0], operands[1])]

def expand_not(operands):
    check_operands_n(operands, 2)
    return ['xor {}, {}, r0, -1'.format(operands[0], operands[1])]

def expand_shift(operands):
    check_operands_n(operands, 3, 4)
    success, imm = parse_imm(operands[2])
    if success and len(operands) == 3:
        if imm < 0:
            return ['shr {}, {}, r0, {}'.format(operands[0], operands[1], -imm)]
        return ['shl {}, {}, r0, {}'.format(operands[0], operands[1], imm)]
    imm = '0' if len(operands) == 3 else operands[3]
    return ['cmple r29, r0, {}, {}'.format(operands[2], imm),
            'beq r29, r0, 8',
            'shl {}, {}, {}, {}'.format(operands[0], operands[1], operands[2], imm),
            'jl r29, 8',
            'sub r29, r0, {}, {}'.format(operands[2], imm),
            'shr {}, {}, r29, 0'.format(operands[0], operands[1])]

def expand_cmpgt(operands):
    check_operands_n(operands, 3)
    if is_reg(operands[2]):
        return ['cmplt {}, {}, {}, 0'.format(operands[0], operands[2], operands[1])]
    success, imm = parse_imm(operands[2])
    if success:
        return mov_imm('r29', imm) + ['cmplt {}, r29, {}, 0'.format(operands[0], operands[1])]
    error('invalid syntax')

def expand_cmpge(operands):
    check_operands_n(operands, 3)
    if is_reg(operands[2]):
        return ['cmple {}, {}, {}, 0'.format(operands[0], operands[2], operands[1])]
    success, imm = parse_imm(operands[2])
    if success:
        return mov_imm('r29', imm) + ['cmple {}, r29, {}, 0'.format(operands[0], operands[1])]
    error('invalid syntax')

def expand_fcmpgt(operands):
    check_operands_n(operands, 3)
    return ['fcmplt {}, {}, {}'.format(operands[0], operands[2], operands[1])]

def expand_fcmpge(operands):
    check_operands_n(operands, 3)
    return ['fcmple {}, {}, {}'.format(operands[0], operands[2], operands[1])]

def expand_read(operands):
    check_operands_n(operands, 1)
    return ['ld r29, r0, 0x3000',
            'beq r29, r0, -8',
            'ld {}, r0, 0x3004'.format(operands[0])]

def expand_write(operands):
    check_operands_n(operands, 1)
    return ['ld r29, r0, 0x3008',
            'beq r29, r0, -8',
            'st {}, r0, 0x300c'.format(operands[0])]

def expand_br(operands):
    check_operands_n(operands, 1)
    return ['jl r29, {}'.format(operands[0])]

def expand_bz(operands, pred):
    check_operands_n(operands, 2)
    return ['beq{} {}, r0, {}'.format(pred, operands[0], operands[1])]

def expand_bnz(operands, pred):
    check_operands_n(operands, 2)
    return ['bne{} {}, r0, {}'.format(pred, operands[0], operands[1])]

# bne, beq
def expand_bne(op, operands, pred):
    check_operands_n(operands, 3)
    success, imm = parse_imm(operands[1])
    if success:
        return mov_imm('r29', imm) + ['{}{} {}, r29, {}'.format(op, pred, operands[0], operands[2])]
    return ['{}{} {}'.format(op, pred, ', '.join(operands))]

# blt, ble, bgt, bge
def expand_blt(op, operands, pred):
    check_operands_n(operands, 3)
    b, c = ('beq', 'cmple') if op == 'bgt' else \
           ('beq', 'cmplt') if op == 'bge' else \
           ('bne', 'cmp' + op[1:])
    return expand_alu(c, ['r29'] + operands[:2]) + ['{}{} r29, r0, {}'.format(b, pred, operands[2])]

# bfne, bfeq, bflt, bfle, bfgt, bfge
def expand_bfne(op, operands, pred):
    check_operands_n(operands, 3)
    b, c = ('beq', 'fcmple') if op == 'bfgt' else \
           ('beq', 'fcmplt') if op == 'bfge' else \
           ('bne', 'fcmp' + op[2:])
    return ['{} r29, {}, {}'.format(c, operands[0], operands[1]),
            '{}{} r29, r0, {}'.format(b, pred, operands[2])]

def expand_push(operands):
    check_operands_n(operands, 1)
    return ['sub rsp, rsp, r0, 4',
            'st {}, rsp, 0'.format(operands[0])]

def expand_pop(operands):
    check_operands_n(operands, 1)
    return ['ld {}, rsp, 0'.format(operands[0]),
            'add rsp, rsp, r0, 4']

def expand_call(operands):
    check_operands_n(operands, 1)
    if is_reg(operands[0]):
        return ['st rbp, rsp, -4',
                'sub rsp, rsp, r0, 4',
                'add rbp, rsp, r0, 0',
                'jl r28, 0',
                'add r28, r28, r0, 8',
                'jr {}'.format(operands[0]),
                'add rsp, rbp, r0, 4',
                'ld rbp, rsp, -4']
    return ['st rbp, rsp, -4',
            'sub rsp, rsp, r0, 4',
            'add rbp, rsp, r0, 0',
            'jl r28, {}'.format(operands[0]),
            'add rsp, rbp, r0, 4',
            'ld rbp, rsp, -4']

def expand_ret(operands):
    check_operands_n(operands, 0)
    return ['jr r28']

def expand_enter(operands):
    check_operands_n(operands, 1)
    success, imm = parse_imm(operands[0])
    if success:
        return expand_alu('sub', ['rsp', 'rsp', str(imm + 4)]) + ['st r28, rsp, 0']
    error('expected integer literal: ' + operands[0])

def expand_leave(operands):
    check_operands_n(operands, 0)
    return ['ld r28, rsp, 0']

def expand_halt(operands):
    check_operands_n(operands, 0)
    return ['beq+ r31, r31, -4']

def expand_dot_int(operands):
    check_operands_n(operands, 1, 2)
    if len(operands) == 1:
        return ['.int ' + operands[0]]
    success, imm = parse_imm(operands[1])
    if not success:
        error('expected integer literal: ' + operands[1])
    return ['.int ' + operands[0]] * imm

def expand_dot_float(operands):
    check_operands_n(operands, 1, 2)
    if len(operands) == 1:
        return ['.float ' + operands[0]]
    success, imm = parse_imm(operands[1])
    if not success:
        error('expected integer literal: ' + operands[1])
    return ['.float ' + operands[0]] * imm

macro_table = {
    'nop':      expand_nop,
    'mov':      expand_mov,
    'and':      expand_and,
    'neg':      expand_neg,
    'not':      expand_not,
    'shift':    expand_shift,
    'cmpgt':    expand_cmpgt,
    'cmpge':    expand_cmpge,
    'fcmpgt':   expand_fcmpgt,
    'fcmpge':   expand_fcmpge,
    'read':     expand_read,
    'write':    expand_write,
    'br':       expand_br,
    'push':     expand_push,
    'pop':      expand_pop,
    'call':     expand_call,
    'ret':      expand_ret,
    'enter':    expand_enter,
    'leave':    expand_leave,
    'halt':     expand_halt,
    '.int':     expand_dot_int,
    '.float':   expand_dot_float,
}

def expand_macro(mnemonic, operands):
    if mnemonic in macro_table:
        return macro_table[mnemonic](operands)
    if mnemonic in ['add', 'sub', 'shl', 'shr', 'sar', 'or', 'xor', 'cmpne', 'cmpeq', 'cmplt', 'cmple']:
        return expand_alu(mnemonic, operands)
    m = re.match(r'(\w+)([+-]?)$', mnemonic)
    if m:
        br_mnemonic, pred = m.groups()
        if br_mnemonic == 'bz':
            return expand_bz(operands, pred)
        if br_mnemonic == 'bnz':
            return expand_bnz(operands, pred)
        if br_mnemonic in ['bne', 'beq']:
            return expand_bne(br_mnemonic, operands, pred)
        if br_mnemonic in ['blt', 'ble', 'bgt', 'bge']:
            return expand_blt(br_mnemonic, operands, pred)
        if br_mnemonic in ['bfne', 'bfeq', 'bflt', 'bfle', 'bfgt', 'bfge']:
            return expand_bfne(br_mnemonic, operands, pred)
    return ['{} {}'.format(mnemonic, ', '.join(operands)).strip()]


# ----------------------------------------------------------------------
#       label resolution
# ----------------------------------------------------------------------

labels = {}
rev_labels = {}
library = ''
entry_point = 0x4000

def add_label(label, i):
    dic = labels.get(label, {})
    if filename in dic and dic[filename][0] >= 0:
        error('duplicate declaration of label \'{}\''.format(label))
    val = dic.get(filename, [-1, False, False])
    dic[filename] = [i, val[1], False]
    labels[label] = dic
    rev_labels[i] = rev_labels.get(i, []) + [label]

def add_global(label):
    dic = labels.get(label, {})
    val = dic.get(filename, [-1, False, False])
    dic[filename] = [val[0], True, False]
    labels[label] = dic

def check_global(label):
    if labels[label][filename][0] < 0:
        error('label \'{}\' is not declared'.format(label))

def subst(label, cur, rel):
    if parse_imm(label)[0]:
        return label
    if label not in labels:
        error('label \'{}\' is not declared'.format(label))
    offset = -4 * (cur + 1) if rel else entry_point
    if filename in labels[label]:
        labels[label][filename][2] = True
        return str(4 * labels[label][filename][0] + offset)
    else:
        decl = ''
        for key in labels[label]:
            if labels[label][key][1]:
                if decl:
                    error('label \'{}\' is declared in multiple files ({}, {})'.format(label, decl, key))
                decl = key
        if not decl:
            error('label \'{}\' is not declared'.format(label))
        labels[label][decl][2] = True
        return str(4 * labels[label][decl][0] + offset)

def warn_unused_label(label):
    if not labels[label][filename][2] and not (filename == library and labels[label][filename][1]):
        print >> sys.stderr, '{}:{}: warning: unused label \'{}\''.format(filename, pos, label)

def show_label(i):
    if i in rev_labels:
        return '# {}'.format(', '.join(rev_labels[i]))
    return ''


# ----------------------------------------------------------------------
#       main process
# ----------------------------------------------------------------------

# parse command line arguments
argparser = argparse.ArgumentParser(usage='%(prog)s [options] file...')
argparser.add_argument('inputs', nargs='*', help='input files', metavar='file...')
argparser.add_argument('-a', help='output as rs232c send test format', action='store_true')
argparser.add_argument('-e', help='set entry point address', metavar='<integer>')
argparser.add_argument('-k', help='output as array of std_logic_vector format', action='store_true')
argparser.add_argument('-l', help='set library file to <file>', metavar='<file>')
argparser.add_argument('-n', help='assure long label assignment does not appear', action='store_true')
argparser.add_argument('-o', help='set output file to <file>', metavar='<file>')
argparser.add_argument('-s', help='output preprocessed assembly', action='store_true')
args = argparser.parse_args()
if args.inputs == []:
    argparser.print_help(sys.stderr)
    sys.exit(1)
if not args.o:
    m = re.match(r'(.*)\.', args.inputs[0])
    args.o = '{}.out'.format(m.group(1) if m else args.inputs[0])
if args.e:
    success, entry_point = parse_imm(args.e)
    if not success:
        argparser.print_usage(sys.stderr)
        print >> sys.stderr, 'error: argument -e: expected integer:', args.e
        sys.exit(1)
    if entry_point & 3 != 0:
        argparser.print_usage(sys.stderr)
        print >> sys.stderr, 'error: argument -e: entry address must be a multiple of 4'
        sys.exit(1)
if args.l:
    args.inputs = [args.l] + args.inputs
    library = re.sub(r'.*[/\\]', '', args.l)

# 0. preprocess
lines0 = []
for filename in args.inputs:
    if not os.path.isfile(filename):
        print >> sys.stderr, 'error: file does not exist:', filename
        sys.exit(1)
    with open(filename, 'r') as f:
        filename = re.sub(r'.*[/\\]', '', filename)
        srcs[filename] = {}
        for pos, line in enumerate(f):
            line = line.strip()
            srcs[filename][pos + 1] = line
            line = re.sub(r'[;#].*', '', line).strip()
            if line:
                lines0.append((line, filename, pos + 1))

# 1. macro expansion
lines1 = []
for line, filename, pos in lines0:
    mnemonic, operands = parse(line)
    lines = expand_macro(mnemonic, operands)
    lines1.extend(map(lambda x: (x, filename, pos), lines))

# 2. label resolution (by 2-pass algorithm)
i = 3
lines2 = [('__movl main, main', '_main', 0), ('', '', 0), ('jr r29', '', 0)]
lines3 = []
movl_long = False
if not args.n and len(lines1) >= (0x8000 - entry_point) >> 2:
    movl_long = True
for line, filename, pos in lines1:
    mnemonic, operands = parse(line)
    if mnemonic[-1] == ':':
        if len(operands) > 0:
            error('label declaration must be followed by new line')
        add_label(line[:-1], i)
    elif mnemonic == '.global':
        check_operands_n(operands, 1)
        add_global(operands[0])
    elif mnemonic == '__movl' and movl_long:
        i += 2
        lines2.extend([(line, filename, pos), ('', filename, pos)])
    else:
        i += 1
        lines2.append((line, filename, pos))
next_line = ''
for i, (line, filename, pos) in enumerate(lines2):
    if next_line:
        lines3.append((next_line, filename, pos))
        next_line = ''
    else:
        mnemonic, operands = parse(line)
        if mnemonic in ['ld', 'st', '.int', '__movl']:
            check_operands_n(operands, 1, 3)
            operands[-1] = subst(operands[-1], i, False)
            if mnemonic == '__movl':
                if movl_long or operands[0] == 'main':
                    if operands[0] == 'main':
                        operands[0] = 'r29'
                    next_line = 'ldh {0}, {0}, {1}'.format(operands[0], int(operands[1]) >> 16)
                    operands[1] = str(int(operands[1]) & 0xffff)
                elif not check_imm_range(int(operands[1]), 16):
                    error('label out of range')
                mnemonic = 'ldl'
        if mnemonic in ['jl', 'bne', 'bne-', 'bne+', 'beq', 'beq-', 'beq+']:
            check_operands_n(operands, 2, 3)
            operands[-1] = subst(operands[-1], i, True)
        lines3.append(('{} {}'.format(mnemonic, ', '.join(operands)), filename, pos))
for line, filename, pos in lines1:
    mnemonic, operands = parse(line)
    if mnemonic[-1] == ':':
        warn_unused_label(line[:-1])
    if mnemonic == '.global':
        check_global(operands[0])

# 3. assemble
with open(args.o, 'w') as f:
    for i, (line, filename, pos) in enumerate(lines3):
        mnemonic, operands = parse(line)
        byterepr = code(mnemonic, operands)
        if args.k:
            f.write("{} => x\"{}\",\n".format(i, ''.join('{:02x}'.format(ord(x)) for x in byterepr)))
        elif args.a:
            fmt = """
            wait for BR; RS_RX <= '0';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '{}';
            wait for BR; RS_RX <= '1';

            wait for (2 * BR);

            """
            for b in byterepr:
                a = ord(b)
                ps = ['1' if a & (1 << j) else '0' for j in range(8)]
                f.write(fmt.format(*ps))
        else:
            f.write(byterepr)
    if args.k:
        f.write("others => (others => '0')\n")
if args.s:
    with open(args.o + '.s', 'w') as f:
        for i, (line, filename, pos) in enumerate(lines3):
            mnemonic, operands = parse(line)
            f.write('{:#08x}  {:7} {:17} {}'.format(
                entry_point + 4 * i,
                mnemonic,
                ', '.join(operands),
                show_label(i)).strip() + '\n'
            )

