gcc vuln.c -o vuln -fcf-protection=none -no-pie -Wl,-z,norelro
# No leaks example - with stack cookies turned off
gcc vuln_2.c -o vuln_2 -fcf-protection=none -no-pie -Wl,-z,norelro -fno-stack-protector
