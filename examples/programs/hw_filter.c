#include <stdint.h>

int prog(uint64_t *ctx, int mem_size, uint64_t *s, int state_size) {
  // Filter over 100 MB of uint64_ts and match on the value 5
  return delilah_hw_filter_eq(ctx, ctx, 1024 * 100 / 8 / 4, 5);
}
