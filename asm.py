#!/usr/bin/env python2.7

import sys
import os.path
import re
import struct
import argparse


srcs = {}
filename = ''
pos = 0

def error(msg):
    if sys.stderr.isatty():
        print >> sys.stderr, '\x1b[1m{}:{}: \x1b[31merror:\x1b[39m'.format(filename, pos), msg
        sys.stderr.write('\x1b[0m')
    else:
        print >> sys.stderr, '{}:{}: error:'.format(filename, pos), msg
    print >> sys.stderr, '  ' + srcs[filename][pos]
    sys.exit(1)

def warning(msg):
    if sys.stderr.isatty():
        print >> sys.stderr, '\x1b[1m{}:{}: \x1b[35mwarning:\x1b[39m'.format(filename, pos), msg
        sys.stderr.write('\x1b[0m')
    else:
        print >> sys.stderr, '{}:{}: warning:'.format(filename, pos), msg


# ----------------------------------------------------------------------
#       utility functions (mainly parsing)
# ----------------------------------------------------------------------

regs = {'rsp': 30, 'rbp': 31}
for i in range(32):
    regs['r' + str(i)] = i

def is_reg(operand):
    return operand in regs

def regnum(reg):
    if reg not in regs:
        error('expected register: ' + reg)
    return regs[reg]

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
        return struct.unpack('>I', s)[0]
    except OverflowError:
        error('floating point value is too large')

def parse_memaccess(operand):
    m = re.match(r'\[(r\w+)\s*([+-])\s*(\w+)\]$', operand)
    if m:
        base = m.group(1)
        disp = m.group(2) + m.group(3)
        if is_reg(base) and parse_imm(disp)[0]:
            return True, base, disp
    m = re.match(r'\[(r\w+)\]$', operand)
    if m and is_reg(m.group(1)):
        return True, m.group(1), '0'
    m = re.match(r'\[([+-]?\w+)\]$', operand)
    if m and parse_imm(m.group(1))[0]:
        return True, 'r0', m.group(1)
    return False, 'r0', '0'

def check_operands_n(operands, n, m=-1):
    l = len(operands)
    if l < n:
        error('expected {} operands, but {} given'.format(n, l))
    if l > max(n, m):
        error('expected {} operands, but {} given'.format(max(n, m), l))

def parse(line):
    line = line.strip()
    if ' ' not in line:
        return line, []
    mnemonic, rest = line.split(None, 1)
    operands = rest.split(',')
    return mnemonic, map(str.strip, operands)


# ----------------------------------------------------------------------
#       mnemonic definitions
# ----------------------------------------------------------------------

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

# misc0_table = {
#     'sysenter':  4,
#     'sysexit':   5,
# }

misc1_table = {
    'jr':       12,
}

misc2_table = {
    'ldl':       2,
    'jl':       11,
}

misc3_table = {
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
            error('displacement must be a multiple of 4')
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

# def on_misc0(operands, op, pred):
#     check_operands_n(operands, 2)
#     return code_m(op, 'r0', 'r0', pred, '0')

def on_misc1(operands, op, pred, disp_mode):
    check_operands_n(operands, 1)
    return code_m(op, operands[0], 'r0', pred, '0', disp_mode)

def on_misc2(operands, op, pred, disp_mode):
    check_operands_n(operands, 2)
    return code_m(op, operands[0], 'r0', pred, operands[1], disp_mode)

def on_misc3(operands, op, pred, disp_mode):
    check_operands_n(operands, 3)
    return code_m(op, operands[0], operands[1], pred, operands[2], disp_mode)

def on_dot_int(operand):
    success, imm = parse_imm(operand[0])
    if not success:
        error('expected integer literal: ' + operands[0])
    if not -0x80000000 <= imm <= 0xffffffff:
        error('immediate value (' + operand + ') is too large')
    cnt = int(operands[1], 0)
    return (chr(imm >> 24 & 255) + chr(imm >> 16 & 255) + chr(imm >> 8 & 255) + chr(imm & 255)) * cnt

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
    # if mnemonic in misc0_table:
    #     return on_misc0(operands, misc0_table[mnemonic], pred, disp_mode)
    if mnemonic in misc1_table:
        return on_misc1(operands, misc1_table[mnemonic], pred, disp_mode)
    if mnemonic in misc2_table:
        return on_misc2(operands, misc2_table[mnemonic], pred, disp_mode)
    if mnemonic in misc3_table:
        return on_misc3(operands, misc3_table[mnemonic], pred, disp_mode)
    if mnemonic == '.int':
        return on_dot_int(operands)
    error('unknown mnemonic \'{}\''.format(mnemonic))


# ----------------------------------------------------------------------
#       macro definitions
# ----------------------------------------------------------------------

def expand_nop(operands):
    check_operands_n(operands, 0)
    return [('add', ['r0', 'r0', 'r0', '0'])]

def mov_imm(dest, imm):
    if check_imm_range(imm, 16):
        return [('ldl', [dest, str(imm)])]
    if imm & 0xffff == 0:
        return [('ldh', [dest, 'r0', str((imm >> 16) & 0xffff)])]
    return [('ldl', [dest, str(imm & 0xffff)]),
            ('ldh', [dest, dest, str((imm >> 16) & 0xffff)])]

def expand_mov(operands):
    check_operands_n(operands, 2)
    if is_reg(operands[0]) and is_reg(operands[1]):
        return [('add', [operands[0], operands[1], 'r0', '0'])]
    if operands[1][0] == '[' and operands[1][-1] == ']':
        success, base, disp = parse_memaccess(operands[1])
        if success:
            return [('ld', [operands[0], base, disp])]
        return [('ld', [operands[0], 'r0', operands[1][1:-1]])]
    if operands[0][0] == '[' and operands[0][-1] == ']':
        pre = []
        success, imm = parse_imm(operands[1])
        if success:
            pre = mov_imm('r29', imm)
            operands[1] = 'r29'
        success, base, disp = parse_memaccess(operands[0])
        if success:
            return pre + [('st', [operands[1], base, disp])]
        return pre + [('st', [operands[1], 'r0', operands[0][1:-1]])]
    success, imm = parse_imm(operands[1])
    if success:
        return mov_imm(operands[0], imm)
    success, imm = parse_float(operands[1])
    if success:
        return mov_imm(operands[0], float_to_bit(imm))
    if is_reg(operands[0]):
        return [('__movl', operands)]
    error('invalid syntax')

# and, sub, shl, shr, sar, or, xor, cmpne, cmpeq, cmplt, cmple
def expand_alu(op, operands):
    check_operands_n(operands, 3, 4)
    if (len(operands) == 4):
        return [(op, operands)]
    if is_reg(operands[2]):
        return [(op, operands + ['0'])]
    success, imm = parse_imm(operands[2])
    if success:
        if check_imm_range(imm, 8):
            return [(op, [operands[0], operands[1], 'r0', operands[2]])]
        return mov_imm('r29', imm) + [(op, [operands[0], operands[1], 'r29', '0'])]
    error('invalid syntax')

def expand_and(operands):
    check_operands_n(operands, 3, 4)
    if (len(operands) == 4):
        return [('and', operands)]
    if is_reg(operands[2]):
        return [('and', operands + ['-1'])]
    success, imm = parse_imm(operands[2])
    if success:
        if check_imm_range(imm, 8):
            return [('and', [operands[0], operands[1], operands[1], operands[2]])]
        return mov_imm('r29', imm) + [('and', [operands[0], operands[1], 'r29', '-1'])]
    error('invalid syntax')

def expand_neg(operands):
    check_operands_n(operands, 2)
    return [('sub', [operands[0], 'r0', operands[1], '0'])]

def expand_not(operands):
    check_operands_n(operands, 2)
    return [('xor', [operands[0], operands[1], 'r0', '-1'])]

def expand_cmpgt(operands):
    check_operands_n(operands, 3)
    if is_reg(operands[2]):
        return [('cmplt', [operands[0], operands[2], operands[1], '0'])]
    success, imm = parse_imm(operands[2])
    if success:
        return mov_imm('r29', imm) + [('cmplt', [operands[0], 'r29', operands[1], '0'])]
    error('invalid syntax')

def expand_cmpge(operands):
    check_operands_n(operands, 3)
    if is_reg(operands[2]):
        return [('cmple', [operands[0], operands[2], operands[1], '0'])]
    success, imm = parse_imm(operands[2])
    if success:
        return mov_imm('r29', imm) + [('cmple', [operands[0], 'r29', operands[1], '0'])]
    error('invalid syntax')

def expand_fcmpgt(operands):
    check_operands_n(operands, 3)
    return [('fcmplt', [operands[0], operands[2], operands[1]])]

def expand_fcmpge(operands):
    check_operands_n(operands, 3)
    return [('fcmple', [operands[0], operands[2], operands[1]])]

def expand_read(operands):
    check_operands_n(operands, 1)
    return [('ld', ['r29', 'r0', '0x3000']),
            ('beq', ['r29', 'r0', '-8']),
            ('ld', [operands[0], 'r0', '0x3004'])]

def expand_write(operands):
    check_operands_n(operands, 1)
    return [('ld', ['r29', 'r0', '0x3008']),
            ('beq', ['r29', 'r0', '-8']),
            ('st', [operands[0], 'r0', '0x300c'])]

def expand_br(operands):
    check_operands_n(operands, 1)
    return [('jl', ['r29', operands[0]])]

def expand_bz(operands, pred):
    check_operands_n(operands, 2)
    return [('beq' + pred, [operands[0], 'r0', operands[1]])]

def expand_bnz(operands, pred):
    check_operands_n(operands, 2)
    return [('bne' + pred, [operands[0], 'r0', operands[1]])]

# bne, beq
def expand_bne(op, operands, pred):
    check_operands_n(operands, 3)
    success, imm = parse_imm(operands[1])
    if success:
        return mov_imm('r29', imm) + [(op + pred, [operands[0], 'r29', operands[2]])]
    return [(op + pred, operands)]

# blt, ble, bgt, bge
def expand_blt(op, operands, pred):
    check_operands_n(operands, 3)
    b, c = ('beq', 'cmple') if op == 'bgt' else \
           ('beq', 'cmplt') if op == 'bge' else \
           ('bne', 'cmp' + op[1:])
    return expand_alu(c, ['r29', operands[0], operands[1]]) + [(b + pred, ['r29', 'r0', operands[2]])]

# bfne, bfeq, bflt, bfle, bfgt, bfge
def expand_bfne(op, operands, pred):
    check_operands_n(operands, 3)
    b, c = ('beq', 'fcmple') if op == 'bfgt' else \
           ('beq', 'fcmplt') if op == 'bfge' else \
           ('bne', 'fcmp' + op[2:])
    return [(c, ['r29', operands[0], operands[1]]),
            (b + pred, ['r29', 'r0', operands[2]])]

def expand_push(operands):
    check_operands_n(operands, 1)
    return [('sub', ['rsp', 'rsp', 'r0', '4']),
            ('st', [operands[0], 'rsp', '0'])]

def expand_pop(operands):
    check_operands_n(operands, 1)
    return [('ld', [operands[0], 'rsp', '0']),
            ('add', ['rsp', 'rsp', 'r0', '4'])]

def expand_call(operands):
    check_operands_n(operands, 1)
    pre  = [('st', ['rbp', 'rsp', '-4']),
            ('sub', ['rsp', 'rsp', 'r0', '4']),
            ('add', ['rbp', 'rsp', 'r0', '0'])]
    post = [('add', ['rsp', 'rbp', 'r0', '4']),
            ('ld', ['rbp', 'rsp', '-4'])]
    if is_reg(operands[0]):
        jump = [('jl', ['r28', '0']),
                ('add', ['r28', 'r28', 'r0', '8']),
                ('jr', operands)]
        return pre + jump + post
    return pre + [('jl', ['r28', operands[0]])] + post

def expand_ret(operands):
    check_operands_n(operands, 0)
    return [('jr', ['r28'])]

def expand_enter(operands):
    check_operands_n(operands, 1)
    success, imm = parse_imm(operands[0])
    if success:
        return expand_alu('sub', ['rsp', 'rsp', str(imm + 4)]) + [('st', ['r28', 'rsp', '0'])]
    error('expected integer literal: ' + operands[0])

def expand_leave(operands):
    check_operands_n(operands, 0)
    return [('ld', ['r28', 'rsp', '0'])]

def expand_halt(operands):
    check_operands_n(operands, 0)
    return [('beq+', ['r31', 'r31', '-4'])]

def expand_dot_int(operands):
    check_operands_n(operands, 1, 2)
    if len(operands) == 2:
        return [('.int', operands)]
    return [('.int', [operands[0], '1'])]

def expand_dot_float(operands):
    check_operands_n(operands, 1, 2)
    success, imm = parse_float(operands[0])
    if not success:
        error('expected floating point literal: ' + operands[0])
    operands[0] = '{:#010x}'.format(float_to_bit(imm))
    return expand_dot_int(operands)

macro_table = {
    'nop':      expand_nop,
    'mov':      expand_mov,
    'and':      expand_and,
    'neg':      expand_neg,
    'not':      expand_not,
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

def expand_macro(line):
    mnemonic, operands = parse(line)
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
    return [(mnemonic, operands)]


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

def init_label(lines, jump_main, long_label):
    global labels, rev_labels, filename, pos
    labels = {}
    rev_labels = {}
    ret = []
    if jump_main:
        ret.extend([('__movl', ['main', 'main'], '', 0), ('', [], '', 0), ('jr', ['r29'], '', 0)])
    i = len(ret)
    for mnemonic, operands, filename, pos in lines:
        if mnemonic[-1] == ':':
            if len(operands) > 0:
                error('label declaration must be followed by new line')
            add_label(mnemonic[:-1], i)
        elif mnemonic == '.align':
            check_operands_n(operands, 1)
            success, imm = parse_imm(operands[0])
            if not success:
                error('expected integer literal: ' + operands[0])
            if imm < 4 or (imm & (imm - 1)) > 0:
                error('invalid alignment')
            padding = imm - ((entry_point + (i << 2)) & (imm - 1));
            if padding < imm:
                i += padding >> 2
                ret.append(('.int', ['0', str(padding >> 2)], filename, pos))
        elif mnemonic == '.global':
            check_operands_n(operands, 1)
            add_global(operands[0])
        elif mnemonic == '.int':
            check_operands_n(operands, 2)
            success, imm = parse_imm(operands[1])
            if not success:
                error('expected integer literal: ' + operands[1])
            i += imm
            ret.append((mnemonic, operands, filename, pos))
        elif mnemonic == '__movl' and long_label:
            i += 2
            ret.extend([(mnemonic, operands, filename, pos), ('', [], filename, pos)])
        else:
            i += 1
            ret.append((mnemonic, operands, filename, pos))
    return i, ret

def label_addr(label, cur, rel):
    if parse_imm(label)[0]:
        return label
    decl = []
    offset = -4 * (cur + 1) if rel else entry_point
    if label in labels:
        for key in labels[label]:
            if key == filename or labels[label][key][1]:
                decl += [key]
    if len(decl) == 0:
        if label == 'main':
            print >> sys.stderr, 'asm: error: global label \'main\' is required'
            sys.exit(1)
        else:
            error('label \'{}\' is not declared'.format(label))
    if len(decl) > 1:
        msg = 'label \'{}\' is declared in multiple files ({})'.format(label, ', '.join(sorted(decl)))
        if label == 'main':
            print >> sys.stderr, 'asm: error:', msg
            sys.exit(1)
        else:
            error(msg)
    labels[label][decl[0]][2] = True
    return str(4 * labels[label][decl[0]][0] + offset)

def check_global(label):
    if labels[label][filename][0] < 0:
        error('label \'{}\' is not declared'.format(label))

def warn_unused_label(label):
    if not labels[label][filename][2] and not (filename == library and labels[label][filename][1]):
        warning('unused label \'{}\''.format(label))

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
argparser.add_argument('-f', help='append label to end of program', metavar='<label>')
argparser.add_argument('-k', help='output as array of std_logic_vector format', action='store_true')
argparser.add_argument('-l', help='set library file to <file>', metavar='<file>')
argparser.add_argument('-n', help='assure long label assignment does not appear', action='store_true')
argparser.add_argument('-o', help='set output file to <file>', metavar='<file>')
argparser.add_argument('-r', help='do not insert main label jump instruction', action='store_true')
argparser.add_argument('-s', help='output preprocessed assembly', action='store_true')
argparser.add_argument('-w', help='suppress warnings', action='store_true')
args = argparser.parse_args()
if args.inputs == []:
    argparser.print_help(sys.stderr)
    sys.exit(1)
if not args.o:
    args.o = 'a.out'
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
            comment_pos = line.find('#')
            if comment_pos != -1:
                line = line[0 : comment_pos].rstrip()
            if line:
                lines0.append((line, filename, pos + 1))
if args.f:
    lines0.append(('.global ' + args.f, '_end', 0))
    lines0.append((args.f + ':', '_end', 0))

# 1. macro expansion
lines1 = []
for line, filename, pos in lines0:
    lines = expand_macro(line)
    lines1.extend(map(lambda (x, y): (x, y, filename, pos), lines))

# 2. label resolution (by 2-pass algorithm)
long_label = False
i, lines2 = init_label(lines1, not args.r, False)
if entry_point + i * 4 >= 0x8000 and not args.n:
    long_label = True
    lines2 = init_label(lines1, not args.r, True)[1]
lines3 = []
next_line = None
for i, (mnemonic, operands, filename, pos) in enumerate(lines2):
    if next_line:
        lines3.append((next_line[0], next_line[1], filename, pos))
        next_line = None
    else:
        if mnemonic in ['ld', 'st', '.int', '__movl']:
            check_operands_n(operands, 1, 3)
            idx = 0 if mnemonic == '.int' else -1
            operands[idx] = label_addr(operands[idx], i, False)
            if mnemonic == '__movl':
                if long_label or operands[0] == 'main':
                    if operands[0] == 'main':
                        operands[0] = 'r29'
                    next_line = ('ldh', [operands[0], operands[0], str(int(operands[1]) >> 16)])
                    operands[1] = str(int(operands[1]) & 0xffff)
                elif not check_imm_range(int(operands[1]), 16):
                    error('label out of range')
                mnemonic = 'ldl'
        if mnemonic in ['jl', 'bne', 'bne-', 'bne+', 'beq', 'beq-', 'beq+']:
            check_operands_n(operands, 2, 3)
            operands[-1] = label_addr(operands[-1], i, True)
        lines3.append((mnemonic, operands, filename, pos))
for mnemonic, operands, filename, pos in lines1:
    if mnemonic == '.global':
        check_global(operands[0])
    if mnemonic[-1] == ':' and not args.w:
        warn_unused_label(mnemonic[:-1])

# 3. assemble
if args.s:
    with open(args.o + '.s', 'w') as f:
        ofs = 0
        for i, (mnemonic, operands, filename, pos) in enumerate(lines3):
            s = '{:#08x}  {:7} {:17} '.format(entry_point + 4 * (i + ofs), mnemonic, ', '.join(operands))
            print >> f, (s + show_label(i + ofs)).strip()
            if mnemonic == '.int':
                ofs += int(operands[1], 0) - 1
with open(args.o, 'w') as f:
    for i, (mnemonic, operands, filename, pos) in enumerate(lines3):
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

