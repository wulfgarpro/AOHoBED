gcc vuln.c -o vuln -fcf-protection=none -no-pie -Wl,-z,norelro
