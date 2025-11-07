#!/usr/bin/env python3
# hints/disasm.py

import sys

opmap = {
    0x00: ("NOP", 0),
    0x01: ("PUSH_IMM", 1),
    0x02: ("POP_REG", 1),
    0x03: ("MOV_RR", 1),
    0x04: ("ADD_RR", 1),
    0x05: ("SUB_RR", 1),
    0x06: ("CMP_REG_IMM", 2),
    0x07: ("JZ", 2),
    0x08: ("JMP", 2),
    0x09: ("CALL", 1),
    0xF9: ("HALT", 0),
}

def read_u8(b, i):
    return b[i], i + 1

def read_s8(b, i):
    v = b[i]
    if v >= 0x80:
        v -= 0x100
    return v, i + 1

def read_s16_le(b, i):
    lo = b[i]
    hi = b[i + 1]
    v = (hi << 8) | lo
    if v >= 0x8000:
        v -= 0x10000
    return v, i + 2

def disasm(b):
    i = 0
    out = []
    while i < len(b):
        op = b[i]; i += 1
        name, _ = opmap.get(op, (f"DB_0x{op:02X}", 0))

        if op == 0x01:  # PUSH_IMM
            val, i = read_s8(b, i)
            out.append(f"{i-2:04x}: PUSH_IMM {val}")

        elif op == 0x02:  # POP_REG
            reg, i = read_u8(b, i)
            out.append(f"{i-2:04x}: POP_REG R{reg & 3}")

        elif op in (0x03, 0x04, 0x05):  # MOV/ADD/SUB with packed dst/src
            b1, i = read_u8(b, i)
            dst = (b1 >> 4) & 0xF
            src = b1 & 0xF
            out.append(f"{i-2:04x}: {name} R{dst & 3},R{src & 3}")

        elif op == 0x06:  # CMP_REG_IMM
            reg, i = read_u8(b, i)
            imm, i = read_s8(b, i)
            out.append(f"{i-3:04x}: CMP_REG_IMM R{reg & 3}, {imm}")

        elif op in (0x07, 0x08):  # JZ / JMP
            off, i = read_s16_le(b, i)
            out.append(f"{i-3:04x}: {name} {off:+d}")

        elif op == 0x09:  # CALL selector
            sel, i = read_u8(b, i)
            out.append(f"{i-2:04x}: CALL 0x{sel:02x}")

        elif op == 0xF9:  # HALT
            out.append(f"{i-1:04x}: HALT")

        else:
            out.append(f"{i-1:04x}: DB 0x{op:02x}")
    return out

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: disasm.py <bytecode.bin>")
        sys.exit(1)
    data = list(open(sys.argv[1], "rb").read())  # list of ints
    for line in disasm(data):
        print(line)
