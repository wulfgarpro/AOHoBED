gcc vuln.c -o vuln -fno-stack-protector -fcf-protection=none -no-pie -z execstack -Wl,-z,norelro
