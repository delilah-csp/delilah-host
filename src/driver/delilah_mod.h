/*******************************************************************************
 *
 * Xilinx XDMA IP Core Linux Driver
 * Copyright(c) 2015 - 2020 Xilinx, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "LICENSE".
 *
 * Karen Xie <karen.xie@xilinx.com>
 *
 ******************************************************************************/

#ifndef __XDMA_MODULE_H__
#define __XDMA_MODULE_H__

#include <linux/aio.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/io_uring.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/splice.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "delilah_uapi.h"
#include "sts_queue.h"
#include "xdma/libxdma.h"

#define MAGIC_ENGINE 0xEEEEEEEEUL
#define MAGIC_DEVICE 0xDDDDDDDDUL

struct delilah_env
{
  struct delilah_dev* delilah;
  uint64_t cid;
};

enum delilah_status
{
  DELILAH_SUCCESS = 0x00,
  DELILAH_NO_SPACE = 0x01,
  DELILAH_INV_PROG_SLOT = 0x02,
  DELILAH_INV_DATA_SLOT = 0x03,
  DELILAH_INV_ADDR = 0x04,
  DELILAH_EBPF_ERROR = 0x05,
  DELILAH_INV_OPCODE = 0x06,
};

struct xdma_channel
{
  struct xdma_dev* xdev;
  struct xdma_engine* engine; /* engine instance, if needed */
};

struct __attribute__((__packed__)) delilah_cfg
{
  uint32_t ehver;
  char ehbld[48];
  uint8_t eheng;
  uint8_t ehpslot;
  uint8_t ehdslot;
  uint8_t rsv0;
  uint64_t ehpsoff;
  uint64_t ehpssze;
  uint64_t ehdsoff;
  uint64_t ehdssze;
};

struct __attribute__((__packed__)) delilah_cmd_req
{
  volatile uint8_t opcode;
  uint8_t rsv0;
  volatile uint16_t cid;
  uint32_t rsv1;
  union
  {
    struct
    {
      volatile uint8_t prog_slot;
      volatile uint8_t data_slot;
      uint16_t rsv;
      volatile uint32_t prog_len;
      volatile uint32_t invalidation_size;
      volatile uint32_t invalidation_offset;
      volatile uint32_t flush_size;
      volatile uint32_t flush_offset;
    } run_prog;

    volatile uint8_t cmd_specific[24];
  };
};

struct __attribute__((__packed__)) delilah_cmd_res
{
  volatile uint16_t cid;
  volatile uint8_t status;
  uint8_t rsv0[5];
  union
  {
    struct
    {
      volatile uint64_t ebpf_ret;
    } run_prog;

    volatile uint8_t cmd_specific[8];
  };
};

struct __attribute__((__packed__)) delilah_cmd
{
  struct delilah_cmd_req req;
  struct delilah_cmd_res res;
};

struct __attribute__((__packed__)) delilah_cmd_ctrl
{
  uint8_t ehcmdexec;
  uint8_t ehcmddone;
  uint8_t rsv[5];
};

struct ida_wq
{
  struct ida ida;
  unsigned int max;
  wait_queue_head_t wq;
};

struct delilah_dev
{
  struct device dev;
  struct pci_dev* pdev;
  struct delilah_pci_dev* hpdev;
  struct cdev cdev;
  int id;

  struct delilah_cfg cfg;
  struct ida prog_slots;
  struct ida data_slots;

  struct ida_wq ebpf_engines_ida_wq;

  struct delilah_cmd __iomem* cmds;
  struct delilah_cmd_ctrl __iomem* cmds_ctrl;
};

/* XDMA PCIe device specific book-keeping */
struct delilah_pci_dev
{
  unsigned long magic;  /* structure ID for sanity checks */
  struct pci_dev* pdev; /* pci device struct from probe() */
  struct xdma_dev* xdev;
  struct delilah_dev* hdev;
  int c2h_channel_max;
  int h2c_channel_max;

  struct xdma_channel xdma_c2h_chnl[XDMA_CHANNEL_NUM_MAX];
  struct xdma_channel xdma_h2c_chnl[XDMA_CHANNEL_NUM_MAX];

  struct ida_wq c2h_ida_wq;
  struct ida_wq h2c_ida_wq;

  uint64_t ehpslen[256];
  struct io_uring_cmd* sqes[256];
};

long delilah_download_program(struct delilah_env* env,
                              struct io_uring_cmd* sqe);
long delilah_exec_program(struct delilah_env* env,
                          struct io_uring_cmd* sqe);
long delilah_io(struct delilah_env* env, struct io_uring_cmd* sqe,
                bool write);

struct xdma_channel *xdma_get_c2h(struct delilah_pci_dev *hpdev);
struct xdma_channel *xdma_get_h2c(struct delilah_pci_dev *hpdev);
void xdma_release_c2h(struct xdma_channel *chnl);
void xdma_release_h2c(struct xdma_channel *chnl);

int delilah_cdev_init(void);
void delilah_cdev_cleanup(void);

void delilah_cdev_destroy(struct delilah_pci_dev* hpdev);
int delilah_cdev_create(struct delilah_pci_dev* hpdev);

#endif /* ifndef __XDMA_MODULE_H__ */
