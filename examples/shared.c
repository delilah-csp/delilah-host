#include "delilah_uapi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <liburing.h>

inline void memset64(char* buffer, uint64_t value)
{
  *(uint64_t*)buffer = value;
}


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
  int src = 42;
  int dst = 0;

  printf("Before: Src: %i\n", src);
  printf("Before: Dst: %i\n", dst);

  // Take an int from the ctx and put in the shared context
  char set_prog[] = {
    0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x2a, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x3a, 0xe8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x4a, 0xe4, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x1a, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa1, 0xe8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x1a, 0xd0, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa1, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x61, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa2, 0xd0, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  // Take an int from the shared context and put in the ctx
  char get_prog[] = {
    0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x2a, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x3a, 0xe8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x4a, 0xe4, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x1a, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa1, 0xe8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x7b, 0x1a, 0xd0, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa1, 0xd0, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x61, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x79, 0xa2, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

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

  /* Submit a DMA command to 0th data slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_DATA_WRITE;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 0, dma->buf = (uint64_t)&src, dma->len = sizeof(int), dma->offset = 0;

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

  /* Get the next free submission queue entry or fail */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 7;
  }

  /* Submit a DMA command to 0th program slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_WRITE;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 0,
    dma->buf = (uint64_t)set_prog, dma->len = 112, dma->offset = 0;

  ret = io_uring_submit(&ring);
  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 8;
  }

  /* Wait for the device to confirm that the program was loaded */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 9;
  }

  /* Inform io_uring that we've received the completion */
  io_uring_cqe_seen(&ring, cqe);

  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  /* Submit a DMA command to 1st program slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_WRITE;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 1,
    dma->buf = (uint64_t)get_prog, dma->len = 112, dma->offset = 0;

  ret = io_uring_submit(&ring);
  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 10;
  }

  /* Wait for the device to confirm that the program was loaded */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 11;
  }

  /* Inform io_uring that we've received the completion */
  io_uring_cqe_seen(&ring, cqe);

  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 12;
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
    return 13;
  }

  /* Wait for the program to finish running */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 14;
  }

  /* Inform io_uring that we've received the completion */
  io_uring_cqe_seen(&ring, cqe);

  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 15;
  }

  /* Prepare the SQE for execution of the program we just offloaded */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_EXEC;

  exec = (struct delilah_exec*)&sqe->cmd;
  exec->prog_slot = 1;           // 0 means use 1st program slot
  exec->data_slot = 1;           // 0 means use 1st data slot
  exec->eng = 1;                 // 0 means use 1st engine
  exec->invalidation_size = 0;   // 0 means invalidate all
  exec->invalidation_offset = 0; // 0 means start at beginning
  exec->flush_size = 0;          // 0 means flush all
  exec->flush_offset = 0;        // 0 means start at beginning

  ret = io_uring_submit(&ring);
  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 16;
  }

  /* Wait for the program to finish running */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 17;
  }

  /* Inform io_uring that we've received the completion */
  io_uring_cqe_seen(&ring, cqe);

  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 18;
  }

  /* Submit a DMA command to 1st data slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_DATA_READ;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 1, dma->buf = (uint64_t)&dst, dma->len = sizeof(int), dma->offset = 0;

  ret = io_uring_submit(&ring);
  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 19;
  }

  /* Wait for the device to confirm that the program was loaded */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 20;
  }

  printf("After: Src: %i\n", src);
  printf("After: Dst: %i\n", dst);

  /* Inform io_uring that we've received the completion */
  io_uring_cqe_seen(&ring, cqe);

  io_uring_queue_exit(&ring);

  return 0;
}
