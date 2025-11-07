FLAG_XOR_KEY = 0xC7

def encrypt_flag(plain: bytes, r0=0x7A, r1=0x00, selector=0x42):
    """
    Produces ENC_FLAG bytes for use in the VM.
    Mirrors the logic of decrypt_flag_if_allowed().
    """
    derived = ((r0 ^ r1 ^ 0xA5) + selector) & 0xFF
    final_k = derived ^ FLAG_XOR_KEY
    enc = [b ^ final_k for b in plain]
    return enc, final_k


if __name__ == "__main__":
    flag = b"DMI{wh4t_4_w31rd_vm}"
    enc, final_k = encrypt_flag(flag)

    print(f"// Derived key: 0x{final_k:02x}")
    print(", ".join(f"0x{b:02x}" for b in enc))