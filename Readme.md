# MbyteV Reverse Engineering Challenge

A tiny custom bytecode VM for a medium-difficulty reverse-engineering CTF.  
Your goal is to reverse the instruction set and craft bytecode that decrypts and prints the hidden flag.

---

## Build

```bash
make            # builds ./build/mbytev
make release    # optional: strips and copies to ./build/release/mbytev
make clean      # removes build directory

## Run

The VM accepts a bytecode file path (raw bytes).
If no file is given, it runs the embedded (packed) program.

```bash
./build/mbytev <bytecode.bin>
```

## Instruction Set (ISA)

Each opcode is 1 byte, followed by 0–2 operand bytes depending on the instruction.

## Success Condition

To reveal and print the flag:

1. Set R0 = 0x7A
2. Execute CALL 0x42 to decrypt the internal flag
3. Execute HALT to print it

## Minimal Winning Bytecode

Assembly:
```
PUSH_IMM 0x7A
POP_REG 0
CALL 0x42
HALT
```

Hex bytes:
```
01 7A 02 00 09 42 F9
```

## Testing

You can use the included test.sh script to verify basic functionality.

It checks:

The success case prints SUCCESS:

Incorrect conditions print FAIL

No-argument execution doesn’t crash

```bash
./test.sh
```

## Developer Notes

The flag is stored encrypted (ENC_FLAG[]) and only decrypted in a proper CALL 0x42 path.

The key is mixed at runtime to avoid simple static XOR extraction.

To create a new flag: XOR your new flag string with the compile-time key (FLAG_XOR_KEY) and replace ENC_FLAG[] in src/mbytev.c.