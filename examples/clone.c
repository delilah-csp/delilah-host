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
  struct delilah_clone* clone;

  int ret, fd;
  char *src, *dst;

  /* Allocate a buffer for initial data and final data */
  src = malloc(BUF_SIZE);
  dst = malloc(BUF_SIZE);

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

  /* Submit a DMA command to 0th data slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_DATA_WRITE;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 0, dma->buf = (uint64_t)src, dma->len = BUF_SIZE, dma->offset = 0;

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
  sqe->cmd_op = DELILAH_OP_CLONE_SLOT;

  uint8_t slots[] = { 1 }; // Copy to slot 1

  clone = (struct delilah_clone*)&sqe->cmd;
  clone->eng = 0;
  clone->src = 0; // Copy from slot 0
  clone->dst = slots;
  clone->num = 1;
  clone->len = BUF_SIZE;
  clone->src_offset = 0;
  clone->dst_offset = 0;

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

  /* Get the next free submission queue entry or fail */
  sqe = io_uring_get_sqe(&ring);

  if (!sqe) {
    fprintf(stderr, "Cannot get SQE\n");
    return 4;
  }

  /* Submit a DMA command to 1st data slot  */
  sqe->opcode = IORING_OP_URING_CMD;
  sqe->fd = fd;
  sqe->cmd_op = DELILAH_OP_DATA_READ;

  dma = (struct delilah_dma*)&sqe->cmd;
  dma->slot = 1, dma->buf = (uint64_t)dst, dma->len = BUF_SIZE, dma->offset = 0;

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

  /* Compare the buffers */
  if (memcmp(src, dst, BUF_SIZE) == 0) {
    printf("Buffers match!\n");
  } else {
    printf("Buffers do not match!\n");
  }

  io_uring_queue_exit(&ring);

  return 0;
}
