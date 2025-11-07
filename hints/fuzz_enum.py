#!/usr/bin/env python3
# hints/fuzz_enum.py

import subprocess, sys

if len(sys.argv) < 3:
    print("Usage: fuzz_enum.py <binary_file> <template_bytefile>")
    sys.exit(1)

vm = sys.argv[1]
tmpl = sys.argv[2]

base = open(tmpl, "rb").read()
def run(data):
    p = subprocess.run([vm, tmpl], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout + p.stderr

orig = run(base)
print("Original output length:", len(orig))

interesting = []

for b in range(0,256):
    d = bytes([b]) + base[1:]
    out = run(d)
    if out != orig:
        interesting.append((b, out[:200]))
        print("byte 0x%02x changed output (truncated):" % b, out[:200])

print("Found", len(interesting), "interesting bytes:")


