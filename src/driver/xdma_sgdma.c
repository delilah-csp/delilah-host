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
#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#include "xdma_sgdma.h"
#include "xdma/libxdma.h"
#include "xdma/libxdma_api.h"
#include "xdma/xdma_thread.h"
#include <asm/cacheflush.h>
#include <linux/types.h>

#define PAGE_PTRS_PER_SGL (sizeof(struct scatterlist) / sizeof(struct page*))
#define TRANSFER_PARTITION_SIZE (XDMA_PAGE_SIZE * XDMA_ENGINE_XFER_MAX_DESC)

/* Module Parameters */
unsigned int sgdma_timeout = 10;
module_param(sgdma_timeout, uint, 0644);
MODULE_PARM_DESC(sgdma_timeout,
                 "timeout in seconds for sgdma, default is 10 sec.");

extern struct kmem_cache* dma_state_cache;

int
hpdev_init_channels(struct delilah_pci_dev* hpdev)
{
  struct xdma_dev* xdev = hpdev->xdev;
  struct xdma_engine* engine;
  int i;

  /* iterate over channels */
  for (i = 0; i < hpdev->h2c_channel_max; i++) {
    engine = &xdev->engine_h2c[i];

    if (engine->magic != MAGIC_ENGINE)
      continue;

    hpdev->xdma_h2c_chnl[i].engine = engine;
    hpdev->xdma_h2c_chnl[i].xdev = xdev;
  }

  for (i = 0; i < hpdev->c2h_channel_max; i++) {
    engine = &xdev->engine_c2h[i];

    if (engine->magic != MAGIC_ENGINE)
      continue;

    hpdev->xdma_c2h_chnl[i].engine = engine;
    hpdev->xdma_c2h_chnl[i].xdev = xdev;
  }

  return 0;
}

static int
check_transfer_align(struct xdma_engine* engine, const __u64 buf, size_t count,
                     loff_t pos, int sync)
{
  if (!engine) {
    pr_err("Invalid DMA engine\n");
    return -EINVAL;
  }

  /* AXI ST or AXI MM non-incremental addressing mode? */
  if (engine->non_incr_addr) {
    int buf_lsb = (int)((uintptr_t)buf) & (engine->addr_align - 1);
    size_t len_lsb = count & ((size_t)engine->len_granularity - 1);
    int pos_lsb = (int)pos & (engine->addr_align - 1);

    dbg_tfr("AXI ST or MM non-incremental\n");
    dbg_tfr("buf_lsb = %d, pos_lsb = %d, len_lsb = %ld\n", buf_lsb, pos_lsb,
            len_lsb);

    if (buf_lsb != 0) {
      dbg_tfr("FAIL: non-aligned buffer address %llx\n", buf);
      return -EINVAL;
    }

    if ((pos_lsb != 0) && (sync)) {
      dbg_tfr("FAIL: non-aligned AXI MM FPGA addr 0x%llx\n", pos);
      return -EINVAL;
    }

    if (len_lsb != 0) {
      dbg_tfr("FAIL: len %d is not a multiple of %d\n", (int)count,
              (int)engine->len_granularity);
      return -EINVAL;
    }
    /* AXI MM incremental addressing mode */
  } else {
    int buf_lsb = (int)((uintptr_t)buf) & (engine->addr_align - 1);
    int pos_lsb = (int)pos & (engine->addr_align - 1);

    if (buf_lsb != pos_lsb) {
      dbg_tfr("FAIL: Misalignment error\n");
      dbg_tfr("host addr %llx, FPGA addr 0x%llx\n", buf, pos);
      return -EINVAL;
    }
  }

  return 0;
}

static void
char_sgdma_unmap_user_buf(struct xdma_io_cb* cb, bool write)
{
  int i;

  sg_free_table(&cb->sgt);

  if (!cb->pages || !cb->pages_nr)
    return;

  for (i = 0; i < cb->pages_nr; i++) {
    if (cb->pages[i]) {
      if (!write)
        set_page_dirty_lock(cb->pages[i]);
      put_page(cb->pages[i]);
    } else
      break;
  }

  if (i != cb->pages_nr)
    pr_info("sgl pages %d/%u.\n", i, cb->pages_nr);

  kfree(cb->pages);
  cb->pages = NULL;
}

static int
char_sgdma_map_user_buf_to_sgl(struct xdma_io_cb* cb, bool write)
{
  struct sg_table* sgt = &cb->sgt;
  unsigned long len = cb->len;
  void __user* buf = cb->buf;
  struct scatterlist* sg;
  unsigned int pages_nr = (((unsigned long)buf + len + PAGE_SIZE - 1) -
                           ((unsigned long)buf & PAGE_MASK)) >>
                          PAGE_SHIFT;
  int i;
  int rv;

  if (pages_nr == 0)
    return -EINVAL;

  if (sg_alloc_table(sgt, pages_nr, GFP_KERNEL)) {
    pr_err("sgl OOM.\n");
    return -ENOMEM;
  }

  cb->pages = kcalloc(pages_nr, sizeof(struct page*), GFP_KERNEL);
  if (!cb->pages) {
    pr_err("pages OOM.\n");
    rv = -ENOMEM;
    goto err_out;
  }

  rv =
    get_user_pages_fast((unsigned long)buf, pages_nr, 1 /* write */, cb->pages);
  /* No pages were pinned */
  if (rv < 0) {
    pr_err("unable to pin down %u user pages, %d.\n", pages_nr, rv);
    goto err_out;
  }
  /* Less pages pinned than wanted */
  if (rv != pages_nr) {
    pr_err("unable to pin down all %u user pages, %d.\n", pages_nr, rv);
    cb->pages_nr = rv;
    rv = -EFAULT;
    goto err_out;
  }

  for (i = 1; i < pages_nr; i++) {
    if (cb->pages[i - 1] == cb->pages[i]) {
      pr_err("duplicate pages, %d, %d.\n", i - 1, i);
      rv = -EFAULT;
      cb->pages_nr = pages_nr;
      goto err_out;
    }
  }

  sg = sgt->sgl;
  for (i = 0; i < pages_nr; i++, sg = sg_next(sg)) {
    unsigned int offset = offset_in_page(buf);
    unsigned int nbytes = min_t(unsigned int, PAGE_SIZE - offset, len);

    flush_dcache_page(cb->pages[i]);
    sg_set_page(sg, cb->pages[i], nbytes, offset);

    buf += nbytes;
    len -= nbytes;
  }

  if (len) {
    pr_err("Invalid user buffer length. Cannot map to sgl\n");
    return -EINVAL;
  }
  cb->pages_nr = pages_nr;
  return 0;

err_out:
  char_sgdma_unmap_user_buf(cb, write);

  return rv;
}

static void
async_io_handler(unsigned long cb_hndl, int err)
{
  struct xdma_engine* engine;
  struct xdma_dev* xdev;
  struct xdma_io_cb* cb = (struct xdma_io_cb*)cb_hndl;
  struct delilah_dma_state* state = (struct delilah_dma_state*)cb->private;
  ssize_t numbytes = 0;
  ssize_t res, res2;
  int lock_stat;

  if (state == NULL) {
    pr_err("Invalid work struct\n");
    return;
  }

  /* Safeguarding for cancel requests */
  lock_stat = spin_trylock(&state->lock);
  if (!lock_stat) {
    pr_err("state lock not acquired\n");
    goto skip_dev_lock;
  }

  if (false != state->cancel) {
    pr_err("skipping aio\n");
    goto skip_tran;
  }

  engine = state->engine;
  xdev = state->xdev;

  if (!err)
    numbytes =
      xdma_xfer_completion((void*)cb, xdev, engine->channel, cb->write,
                           cb->ep_addr, &cb->sgt, 0, sgdma_timeout * 1000);
  else
    pr_err("DMA transfer failed with error code %d\n", err);

  char_sgdma_unmap_user_buf(cb, cb->write);

  state->res2 |= (err < 0) ? err : 0;
  if (state->res2)
    state->err_cnt++;

  state->cmpl_cnt++;
  state->res += numbytes;

  if (state->cmpl_cnt == state->req_cnt) {
    res = state->res;
    res2 = state->res2;
    io_uring_cmd_done(state->sqe, res2,
                      res2); // res1 is bytes transferred, res2 is error code.
                             // We don't need to return bytes transferred
  skip_tran:
    spin_unlock(&state->lock);
    kmem_cache_free(dma_state_cache, state);
    kfree(cb);
    return;
  }
  spin_unlock(&state->lock);
  return;

skip_dev_lock:
  io_uring_cmd_done(state->sqe, state->err_cnt, state->err_cnt);
  kmem_cache_free(dma_state_cache, state);
}

ssize_t
xdma_channel_read_write(struct io_uring_cmd* sqe, struct xdma_channel* chnl,
                        const __u64 buf, size_t count, loff_t pos, bool write)
{
  struct xdma_engine* engine;
  struct xdma_dev* xdev;
  struct delilah_dma_state* state;
  unsigned long i;
  int rv;

  ssize_t offset;
  ssize_t len;
  ssize_t submissions = count / (TRANSFER_PARTITION_SIZE) +
                        (count % (TRANSFER_PARTITION_SIZE) != 0);

  engine = chnl->engine;
  xdev = chnl->xdev;

  if ((write && engine->dir != DMA_TO_DEVICE) ||
      (!write && engine->dir != DMA_FROM_DEVICE)) {
    pr_err("r/w mismatch. W %d, dir %d.\n", write, engine->dir);
    return -EINVAL;
  }

  state = kmem_cache_alloc(dma_state_cache, GFP_KERNEL);
  memset(state, 0, sizeof(struct delilah_dma_state));

  state->cb = kzalloc(submissions * (sizeof(struct xdma_io_cb)), GFP_KERNEL);

  spin_lock_init(&state->lock);
  state->write = write;
  state->cancel = false;
  state->req_cnt = submissions;
  state->cmpl_cnt = 0;
  state->err_cnt = 0;

  state->engine = engine;
  state->xdev = xdev;
  state->channel = chnl;
  state->sqe = sqe;

  for (i = 0; i < submissions; i++) {
    offset = i * TRANSFER_PARTITION_SIZE;
    len = min_t(size_t, count - offset, TRANSFER_PARTITION_SIZE);

    memset(&(state->cb[i]), 0, sizeof(struct xdma_io_cb));

    state->cb[i].buf = (void __user*)(buf + offset);
    state->cb[i].len = len;
    state->cb[i].ep_addr = (u64)pos + offset;
    state->cb[i].write = write;
    state->cb[i].private = state;
    state->cb[i].io_done = async_io_handler;

    rv = check_transfer_align(engine, (u64)state->cb[i].buf, state->cb[i].len,
                              pos + offset, 1);
    if (rv) {
      pr_info("Invalid transfer alignment detected\n");
      kmem_cache_free(dma_state_cache, state);
      return rv;
    }

    rv = char_sgdma_map_user_buf_to_sgl(&state->cb[i], write);
    if (rv < 0)
      return rv;

    rv = xdma_xfer_submit_nowait((void*)&state->cb[i], xdev, engine->channel,
                                 state->cb[i].write, state->cb[i].ep_addr,
                                 &state->cb[i].sgt, 0, sgdma_timeout * 1000);
  }

  if (engine->cmplthp)
    xdma_kthread_wakeup(engine->cmplthp);

  return -EIOCBQUEUED;
}
