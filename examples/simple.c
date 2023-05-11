#include "delilah_uapi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <liburing.h>

#define BUF_SIZE 1024 * 1024

int
main()
{
  struct io_uring ring;
  struct io_uring_sqe* sqe;
  struct io_uring_cqe* cqe;
  struct io_uring_params p = {};
  struct delilah_dma* dma;
  struct delilah_exec* exec;

  int ret, fd;
  char *src, *dst, *prog;

  /* Allocate a buffer for initial data, final data and program */
  src = malloc(BUF_SIZE * sizeof(char));
  dst = malloc(BUF_SIZE * sizeof(char));
  prog = malloc(16 * sizeof(char));

  if (!src || !dst || !prog) {
    fprintf(stderr, "Failed to allocate buffers\n");
    return 1;
  }

  /* Set initial data buffer to 0xFF */
  memset(src, 0xFF, BUF_SIZE);
  memset(dst, 0x00, BUF_SIZE);

  /*
   * Create an eBPF program with two instructions:
   *     r0 = 0 (b7 00 00 00 00 00 00 00)
   *     ret    (95 00 00 00 00 00 00 00)
   */
  memset(prog, 0, 16);
  prog[0] = 0xb7;
  prog[8] = 0x95;

  p.flags = IORING_SETUP_SQE128;

  /* Initialize io_uring queue with four entries */
  ret = io_uring_queue_init(4, &ring, p.flags);

  if (ret) {
    fprintf(stderr, "Cannot init queue\n");
    return 2;
  }

  /* Open Delilah device */
  fd = open("/dev/delilah0", O_RDWR);
  if (fd < 0) {
    perror("Cannot open Delilah device");
    return 3;
  }

  /* Get the next free submission queue entry or fail */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 4;
  }

  /* Submit a DMA command to 0th program slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_WRITE;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 0, // We only execute a single program, so we know 0 is free.
    dma->buf = (uint64_t)prog, dma->len = 16, dma->offset = 0;

  ret = io_uring_submit(&ring);
  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 5;
  }

  /* Wait for the device to confirm that the program was loaded */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 6;
  }

  /* Inform io_uring that we've received the completion */
  io_uring_cqe_seen(&ring, cqe);

  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 7;
  }

  /* Prepare the SQE for execution of the program we just offloaded */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_EXEC;

  exec = (struct delilah_exec*)&sqe->cmd;
  exec->prog_slot = 0;           // 0 means use 0th program slot
  exec->data_slot = 0;           // 0 means use 0th data slot
  exec->eng = 0;                 // 0 means use 0th engine
  exec->invalidation_size = 0;   // 0 means invalidate all
  exec->invalidation_offset = 0; // 0 means start at beginning
  exec->flush_size = 0;          // 0 means flush all
  exec->flush_offset = 0;        // 0 means start at beginning

  ret = io_uring_submit(&ring);
  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 8;
  }

  /* Wait for the program to finish running */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 9;
  }

  io_uring_cqe_seen(&ring, cqe);
  io_uring_queue_exit(&ring);

  return 0;
}
