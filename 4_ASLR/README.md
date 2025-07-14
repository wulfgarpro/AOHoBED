# README

For `soln2.py` to work, we need the `pop rdi; ret;` gadget in the `vuln_2`. This is only possible
with an older `gcc`, e.g. v9.3.0. I use the Docker image `gcc:9.3.0-buster` for this exercise:

```sh
docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp gcc:9.3.0-buster gcc -o vuln_2 vuln_2.c
```
