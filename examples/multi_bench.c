#include "delilah_uapi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include <liburing.h>

#define BUF_SIZE 1024 * 1024

static inline struct timeval
clock_start()
{
  struct timeval start;
  gettimeofday(&start, NULL);
  return start;
}

static inline double
clock_end(struct timeval start)
{
  struct timeval end;
  gettimeofday(&end, NULL);

  return (end.tv_sec - start.tv_sec) +
         (end.tv_usec - start.tv_usec) / 1000000.0;
}


static char prog1[] = {
    0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// r1 = 0x0
    0x63, 0x1a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,	// *(u32 *)(r10 - 0x4) = r1
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// goto +0x0 <LBB0_1>

    // LBB0_1:
    0x61, 0xa1, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,	// r1 = *(u32 *)(r10 - 0x4)
    0x67, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,	// r1 <<= 0x20
    0xc7, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,	// r1 s>>= 0x20
    0x65, 0x01, 0x06, 0x00, 0x9f, 0x86, 0x01, 0x00,	// if r1 s> 0x1869f goto +0x6 <LBB0_4>
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// goto +0x0 <LBB0_2>

    // LBB0_2:
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// goto +0x0 <LBB0_3>

    // LBB0_3:
    0x61, 0xa1, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,	// r1 = *(u32 *)(r10 - 0x4)
    0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,	// r1 += 0x1
    0x63, 0x1a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,	// *(u32 *)(r10 - 0x4) = r1
    0x05, 0x00, 0xf6, 0xff, 0x00, 0x00, 0x00, 0x00,	// goto -0xa <LBB0_1>

    // LBB0_4:
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// r0 = 0x0
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	// exit
};

static char prog5[] = {
    0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // r1 = 0x0
    0x63, 0x1a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,     // *(u32 *)(r10 - 0x4) = r1
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // goto +0x0 <LBB0_1>

    // LBB0_1:
    0x61, 0xa1, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,     // r1 = *(u32 *)(r10 - 0x4)
    0x67, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,     // r1 <<= 0x20
    0xc7, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,     // r1 s>>= 0x20
    0x65, 0x01, 0x06, 0x00, 0x1f, 0xa1, 0x07, 0x00,     // if r1 s> 0x7a11f goto +0x6 <LBB0_4>
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // goto +0x0 <LBB0_2>

    // LBB0_2:
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // goto +0x0 <LBB0_3>

    // LBB0_3:
    0x61, 0xa1, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,     // r1 = *(u32 *)(r10 - 0x4)
    0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,     // r1 += 0x1
    0x63, 0x1a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,     // *(u32 *)(r10 - 0x4) = r1
    0x05, 0x00, 0xf6, 0xff, 0x00, 0x00, 0x00, 0x00,     // goto -0xa <LBB0_1>

    // LBB0_4:
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // r0 = 0x0
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00      // exit
};

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
  char *src, *dst;

  /* Allocate a buffer for initial data, final data and program */
  src = malloc(BUF_SIZE * sizeof(char));
  dst = malloc(BUF_SIZE * sizeof(char));

  if (!src || !dst) {
    fprintf(stderr, "Failed to allocate buffers\n");
    return 1;
  }

  /* Set initial data buffer to 0xFF */
  memset(src, 0xFF, BUF_SIZE);
  memset(dst, 0x00, BUF_SIZE);

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
    dma->buf = (uint64_t)prog1, dma->len = sizeof(prog1), dma->offset = 0;

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
  dma->slot = 1, // We only execute a single program, so we know 0 is free.
    dma->buf = (uint64_t)prog5, dma->len = sizeof(prog5), dma->offset = 0;

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

  struct timeval prog5_exec_start = clock_start();

  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 10;
  }

  /* Prepare the SQE for execution of the program we just offloaded */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_EXEC_JIT;

  exec = (struct delilah_exec*)&sqe->cmd;
  exec->prog_slot = 1;           // 0 means use 0th program slot
  exec->data_slot = 0;           // 0 means use 0th data slot
  exec->eng = 0;                 // 0 means use 0th engine
  exec->invalidation_size = 1;   // 1 means invalidate 1 byte (minimum)
  exec->invalidation_offset = 0; // 0 means start at beginning
  exec->flush_size = 1;          // 1 means flush 1 byte (minimum)
  exec->flush_offset = 0;        // 0 means start at beginning

  ret = io_uring_submit(&ring);

  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 11;
  }

  /* Wait for the program to finish running */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 12;
  }

  io_uring_cqe_seen(&ring, cqe);

  double prog5_exec_time = clock_end(prog5_exec_start) * 1000;
  printf("1x 500.000 iterations: %.3f ms\n", prog5_exec_time);

  struct timeval prog1_exec_start = clock_start();

  for(int i = 0; i < 5; i++){
  /* Get another SQE */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 10;
  }

  /* Prepare the SQE for execution of the program we just offloaded */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_PROG_EXEC_JIT;

  exec = (struct delilah_exec*)&sqe->cmd;
  exec->prog_slot = 0;           // 0 means use 0th program slot
  exec->data_slot = 0;           // 0 means use 0th data slot
  exec->eng = 0;                 // 0 means use 0th engine
  exec->invalidation_size = 1;   // 1 means invalidate 1 byte (minimum)
  exec->invalidation_offset = 0; // 0 means start at beginning
  exec->flush_size = 1;          // 1 means flush 1 byte (minimum)
  exec->flush_offset = 0;        // 0 means start at beginning

  ret = io_uring_submit(&ring);

  if (ret < 0) {
    fprintf(stderr, "Cannot submit to uring: %s\n", strerror(-ret));
    return 11;
  }

  /* Wait for the program to finish running */
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    fprintf(stderr, "Cannot wait for CQE: %i\n", ret);
    return 12;
  }

  io_uring_cqe_seen(&ring, cqe);
  }

  double prog1_exec_time = clock_end(prog1_exec_start) * 1000;
  printf("5x 100.000 iterations: %.3f ms\n", prog1_exec_time);

  io_uring_queue_exit(&ring);

  return 0;
}
