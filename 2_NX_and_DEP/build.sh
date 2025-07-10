# 32-bit
gcc vuln.c -o vuln_x86 -fno-stack-protector -fcf-protection=none -no-pie -Wl,-z,norelro -m32
# 64-bit
gcc vuln.c -o vuln -fno-stack-protector -fcf-protection=none -no-pie -Wl,-z,norelro
