// #include "gfr.h"

#include <stdlib.h>
#include <cstdio>
#include <unordered_map>

extern "C" void foobar();
extern "C" int c_main(int argc, char* argv[]);

void foobar() {
  std::fprintf(stderr, "Hello world.");
}


int main(int argc, char* argv[]) {
  return c_main(argc, argv);
}
