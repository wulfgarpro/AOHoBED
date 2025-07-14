# README

See notes in [README](../4_ASLR/README.md) from ALSR chapter.

But this time, run:

```sh
docker run --rm -v $pwd:/usr/src/myapp -w /usr/src/myapp gcc:9.3.0-buster gcc -fPIE -pie -fstack-protector vuln.c -o vuln
```
