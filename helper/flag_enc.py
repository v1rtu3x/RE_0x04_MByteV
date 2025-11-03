flag = b"DMI{wh4t_4_w31rd_vm}"
key  = 0xC7
enc  = [b ^ key for b in flag]
print(", ".join(f"0x{b:02x}" for b in enc))