#!/user/bin/env python3
# hints/disasm.py

import sys

opmap = {
    0x00: ("NOP", 0),
    0X01: ("PUSH_IMM", 1),
    0X02: ("POP_REG", 1),
    0X03: ("MOV_RR", 1),
    0X04: ("ADD_RR", 1),
    0X05: ("SUB_RR", 1),
    0X06: ("CMP_REG_IMM", 2),
    0X07: ("JZ", 2),
    0x08: ("JMP", 2),
    0x09: ("CALL", 2),
    0XF9: ("HALT", 0),
}


def read_u8(b, i):
    return b[i], i + 1;

def read_s8(b, i):
    v = b[i]
    if v > 0x80: v -= 0x100
    return v, i + 1

def read_s16_le(b, i):
    lo = b[i]
    hi = b[i+1]
    v = (hi << 8) | lo
    if v >= 0x8000: 
        v -= 0x10000
    return v, i+2

def disasm(b):
    i=0
    out = []
    while i < len(b):
        op = b[i]
        i+=1
        name, args = opmap.get(op, ("DB_0x%02x" % op, 0))
        if op == 0x01:
            val, i = read_s8(b, i)
            out.append(f"{i-2:04x}: PUSH_IMM {val}")
        elif op == 0x02:
            reg, i = read_u8(b, i)
            out.append(f"{i-2:04x}: POP_REG {reg & 3}")
        elif op in (0x03, 0x04, 0x05):
            b1, i = read_u8(b, i)
            dst = (b1 >> 4) & 0xF 
            src = b1 & 0xF
            out.append(f"{i-2:04x}: {name} R{dst&3}, R{src&3}")
        elif op == 0x06:
            reg, i = read_u8(b, i)
            imm, i = read_s8(b, i)
            out.append(f"{i-3:04x}: CMP_REG_IMM R{reg&3}, {imm}")
        elif op in (0x07, 0x08): 
            off, i = read_s16_le(b, i)
            out.append(f"{i-3:04x}: {name} {off:+d}")
        elif op == 0x09:
            sel, i = read_u8(b, i)
            out.append(f"{i-2:04x}: CALL {sel: 02x}")
        elif op == 0xF9:
            out.append(f"{i-1:04x}: HALT")
        else:
            out.append(f"{i-1:04x}: DB 0x{op:02x}")
    return out

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: disasm.py <binary_file>")
        sys.exit(1)
    
    data = open(sys.argv[1], "rb").read()
    for line in disasm(data):
        print(line)


