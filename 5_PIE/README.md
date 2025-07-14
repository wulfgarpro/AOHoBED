# README

See notes in [README](../4_ASLR/README.md) from ALSR chapter.

But this time, run:

```sh
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:9.3.0-buster gcc -fPIE -pie vuln.c -o vuln
```

This enables PIE (and stack cookies) which is disabled by default in older GCC.
