from pwn import *

p = process("./vuln")
e = ELF("./vuln")
rop = ROP(e)

p.wait()
