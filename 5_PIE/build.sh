gcc vuln.c -o vuln -fcf-protection=none -Wl,-z,norelro # PIE by default for newer GCC
