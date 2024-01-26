#include <stdint.h>

int prog(uint64_t *ctx, int mem_size, uint64_t *s, int state_size) {
  uint64_t cmp = 5;
  uint64_t c = 0;

  for(uint64_t i = 0; i < 1024 * 1024 * 100 / 8; i++)
    if(ctx[i] == cmp) ctx[c++] = ctx[i];

  return c;
}
