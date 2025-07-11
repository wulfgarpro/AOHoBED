#include <stdio.h>
#include <string.h>
#include <unistd.h>

void overflow() {
  char name[0x100]; // Who has a name with more than 256 characters?

  // clear the name buffer
  memset(name, 0x00, 0x100);

  // read user's name
  puts("Hey, whats your name!?\n");
  read(STDIN_FILENO, name, 4096);

  // print name back to user
  puts("Welcome ");
  puts(name);
}

int main() {

  overflow();

  return 0;
}
