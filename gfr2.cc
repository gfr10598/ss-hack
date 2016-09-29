// #include "gfr.h"

#include <stdlib.h>
#include <cstdio>
#include <unordered_map>

extern "C" void foobar();

void foobar() {
  std::fprintf(stderr, "Hello world.");
}
