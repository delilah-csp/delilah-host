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

  int ret, fd;
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
  sqe->cmd_op = DELILAH_OP_CLEAR_CACHE;

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
  io_uring_queue_exit(&ring);

  return 0;
}
