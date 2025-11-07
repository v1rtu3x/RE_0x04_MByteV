// src/mbytev.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define STACK_SIZE 512
#define MAX_CODE   4096
#define FLAG_XOR_KEY 0xC7

// Encrypted flag bytes (XOR-packed). Decrypts into dec_flag at runtime.
static const uint8_t ENC_FLAG[] = {
    0xa2, 0xab, 0xaf, 0x9d, 0x91, 0x8e, 
    0xd2, 0x92, 0xb9, 0xd2, 0xb9, 0x91, 
    0xd5, 0xd7, 0x94, 0x82, 0xb9, 0x90, 
    0x8b, 0x9b
};
static const size_t ENC_FLAG_LEN = sizeof(ENC_FLAG);

static char dec_flag[256];     // decrypted flag (NUL-terminated)
static int  flag_unlocked = 0; // set after a proper CALL

// Embedded (XOR-packed) default bytecode program (placeholder)
static const uint8_t packed_code[] = {
    0x00
};
static const size_t packed_len = sizeof(packed_code);

static uint8_t compute_xor_key(void) {
    uint8_t a = 0x12;
    uint8_t b = 0xB5;
    return (uint8_t)(((a ^ b) + 0x11) & 0xFF);
}

static void decrypt_flag_if_allowed(int8_t regs[4], uint8_t selector) {
    if (flag_unlocked) return;
    if ((uint8_t)regs[0] != 0x7A) return;   // R0 must equal 0x7A
    if (selector != 0x42) return;           // selector must equal 0x42

    uint8_t derived = (uint8_t)(((uint8_t)regs[0] ^ (uint8_t)regs[1] ^ 0xA5) + selector);
    uint8_t final_k = (uint8_t)(derived ^ FLAG_XOR_KEY);

    size_t n = (ENC_FLAG_LEN < (sizeof(dec_flag) - 1)) ? ENC_FLAG_LEN : (sizeof(dec_flag) - 1);
    for (size_t i = 0; i < n; ++i) {
        dec_flag[i] = (char)(ENC_FLAG[i] ^ final_k);
    }
    dec_flag[n] = '\0';
    flag_unlocked = 1;
}

enum {
    OP_NOP           = 0x00,
    OP_PUSH_IMM      = 0x01,
    OP_POP_REG       = 0x02,
    OP_MOV_RR        = 0x03,
    OP_ADD_RR        = 0x04,
    OP_SUB_RR        = 0x05,
    OP_CMP_REG_IMM   = 0x06,
    OP_JZ            = 0x07,
    OP_JMP           = 0x08,
    OP_CALL          = 0x09,
    OP_HALT          = 0xF9
};

static int16_t read_s16_le(const uint8_t *code, size_t *ip, size_t code_len) {
    if (*ip + 2 > code_len) return 0;
    uint8_t lo = code[(*ip)++];
    uint8_t hi = code[(*ip)++];
    return (int16_t)(((uint16_t)hi << 8) | lo);
}

int main(int argc, char **argv) {
    uint8_t code[MAX_CODE];
    size_t  code_len = 0;

    // Try external bytecode file first
    if (argc >= 2) {
        const char *path = argv[1];
        FILE *f = fopen(path, "rb");
        if (f) {
            code_len = fread(code, 1, MAX_CODE, f);
            fclose(f);
            if (code_len == 0) {
                fprintf(stderr, "Provided file is empty; falling back to embedded program.\n");
            }
        } else {
            fprintf(stderr, "Could not open '%s'; falling back to embedded program.\n", path);
        }
    }

    // Fallback to embedded packed program
    if (code_len == 0) {
        if (packed_len > MAX_CODE) {
            fprintf(stderr, "Packed program too large\n");
            return 1;
        }
        uint8_t xor_key = compute_xor_key();
        for (size_t i = 0; i < packed_len; ++i) {
            code[i] = (uint8_t)(packed_code[i] ^ xor_key);
        }
        code_len = packed_len;
    }

    // VM state
    size_t ip = 0;
    int8_t regs[4] = {0, 0, 0, 0};
    int16_t stack[STACK_SIZE];
    int sp = 0;
    int zflag = 0;

    while (ip < code_len) {
        uint8_t op = code[ip++];

        switch (op) {
            case OP_NOP:
                break;

            case OP_PUSH_IMM: {
                if (ip >= code_len) { puts("Truncated PUSH"); return 1; }
                int8_t v = (int8_t)code[ip++];
                if (sp >= STACK_SIZE) { puts("Stack overflow"); return 1; }
                stack[sp++] = v;
                break;
            }

            case OP_POP_REG: {
                if (ip >= code_len) { puts("Truncated POP"); return 1; }
                int reg = (int)(code[ip++] & 0x03);
                if (sp == 0) { puts("Stack underflow"); return 1; }
                regs[reg] = (int8_t)stack[--sp];
                break;
            }

            case OP_MOV_RR: {
                if (ip >= code_len) { puts("Truncated MOV"); return 1; }
                uint8_t b = code[ip++];
                int dst = (b >> 4) & 0x0F;
                int src = b & 0x0F;
                regs[dst & 3] = regs[src & 3];
                break;
            }

            case OP_ADD_RR: {
                if (ip >= code_len) { puts("Truncated ADD"); return 1; }
                uint8_t b = code[ip++];
                int dst = (b >> 4) & 0x0F;
                int src = b & 0x0F;
                regs[dst & 3] = (int8_t)(regs[dst & 3] + regs[src & 3]);
                break;
            }

            case OP_SUB_RR: {
                if (ip >= code_len) { puts("Truncated SUB"); return 1; }
                uint8_t b = code[ip++];
                int dst = (b >> 4) & 0x0F;
                int src = b & 0x0F;
                regs[dst & 3] = (int8_t)(regs[dst & 3] - regs[src & 3]);
                break;
            }

            case OP_CMP_REG_IMM: {
                if (ip + 2 > code_len) { puts("Truncated CMP"); return 1; }
                int reg = (int)(code[ip++] & 0x03);
                int8_t imm = (int8_t)code[ip++];
                zflag = (regs[reg] == imm);
                break;
            }

            case OP_JZ: {
                if (ip + 2 > code_len) { puts("Truncated JZ"); return 1; }
                int16_t off = read_s16_le(code, &ip, code_len);
                if (zflag) {
                    int32_t next = (int32_t)ip + (int32_t)off;
                    if (next < 0 || (size_t)next > code_len) { puts("JUMP OOB"); return 1; }
                    ip = (size_t)next;
                }
                break;
            }

            case OP_JMP: {
                if (ip + 2 > code_len) { puts("Truncated JMP"); return 1; }
                int16_t off = read_s16_le(code, &ip, code_len);
                int32_t next = (int32_t)ip + (int32_t)off;
                if (next < 0 || (size_t)next > code_len) { puts("JUMP OOB"); return 1; }
                ip = (size_t)next;
                break;
            }

            case OP_CALL: {
                if (ip >= code_len) { puts("Truncated CALL"); return 1; }
                uint8_t selector = code[ip++];
                decrypt_flag_if_allowed(regs, selector);
                break;
            }

            case OP_HALT: {
                if (flag_unlocked) {
                    printf("SUCCESS: FLAG{%s}\n", dec_flag);
                } else {
                    puts("FAIL");
                }
                return 0;
            }


            default:
                puts("Bad opcode");
                return 1;
        }
    }

    puts("EOF without HALT");
    return 0;
}
