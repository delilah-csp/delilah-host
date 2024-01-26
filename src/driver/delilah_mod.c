/*******************************************************************************
 *
 * Delilah Linux Driver
 * Copyright(c) 2015 - 2020 Xilinx, Inc.
 * Copyright(c) 2022 Niclas Hedam
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
 * Niclas Hedam <nhed@itu.dk>
 *
 ******************************************************************************/

#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/aer.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/ioctl.h>
#include <linux/types.h>
/* include early, to verify it depends only on the headers above */
#include "delilah_mod.h"
#include "xdma/libxdma.h"
#include "xdma/libxdma_api.h"
#include "xdma_sgdma.h"

#define DELILAH_OPCODE_CLEAR_CACHE 0x50
#define DELILAH_OPCODE_CLEAR_STATE 0x51
#define DELILAH_OPCODE_RUN_PROG 0x80
#define DELILAH_OPCODE_RUN_PROG_JIT 0x81

#define DRV_MODULE_VERSION "v0.1"
#define DRV_MODULE_NAME "delilah"
#define DRV_MODULE_DESC "Delilah driver"

static char version[] =
  DRV_MODULE_DESC " " DRV_MODULE_NAME " " DRV_MODULE_VERSION "\n";

MODULE_AUTHOR("Xilinx, Inc.");
MODULE_AUTHOR("Eideticom Inc.");
MODULE_AUTHOR("Niclas Hedam");
MODULE_DESCRIPTION(DRV_MODULE_DESC);
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_LICENSE("GPL v2"); // Eid-hermes (Eideticom) is Apache 2.0, but had this.
                          // Assume this is fine.

/* SECTION: Module global variables */
static int dpdev_cnt;

static const struct pci_device_id pci_ids[] = { {
                                                  PCI_DEVICE(0x1de5, 0x3000),
                                                },
                                                {
                                                  PCI_DEVICE(0x1de5, 0x9038),
                                                },
                                                {
                                                  PCI_DEVICE(0x1de5, 0x9034),
                                                },

                                                {
                                                  PCI_DEVICE(0x719e, 0x1000),
                                                },
                                                {
                                                  0,
                                                } };

MODULE_DEVICE_TABLE(pci, pci_ids);

static void
work_h2c(struct work_struct* work)
{

  struct delilah_queue_entry* entry =
    container_of(work, struct delilah_queue_entry, work);

  struct delilah_pci_dev* dpdev = entry->dpdev;
  struct xdma_channel* chnl;
  struct delilah_cfg* cfg = &dpdev->ddev->cfg;
  const struct delilah_dma* dma;
  off_t pos;

  dma = entry->sqe->cmd;

  pr_debug("H2C: buf: 0x%llx len: 0x%x slot: 0x%x offset: 0x%x, op: 0x%x\n",
           dma->buf, dma->len, dma->slot, dma->offset, entry->sqe->cmd_op);

  if (!access_ok((void*)dma->buf, dma->len)) {
    pr_warn("H2C received an invalid buffer address\n");
    io_uring_cmd_done(entry->sqe, -EINVAL, -EINVAL);
    return;
  }

  chnl = xdma_get_h2c(dpdev);

  if (IS_ERR(chnl)) {
    io_uring_cmd_done(entry->sqe, -EAGAIN, -EAGAIN);
    pr_info("H2C: No channel available\n");
    return;
  }

  // If we handling a program write, we need to write to the program slot
  if (entry->sqe->cmd_op == DELILAH_OP_PROG_WRITE)
    pos = cfg->ehpsoff + dma->slot * cfg->ehpssze;
  else
    pos = cfg->ehdsoff + dma->slot * cfg->ehdssze;

  xdma_channel_read_write(entry->sqe, chnl, dma->buf, dma->len,
                          pos + dma->offset, 1);
  xdma_release_h2c(chnl);

  kfree(entry);

  return;
}

static void
work_c2h(struct work_struct* work)
{
  struct delilah_queue_entry* entry =
    container_of(work, struct delilah_queue_entry, work);

  struct delilah_pci_dev* dpdev = entry->dpdev;
  struct xdma_channel* chnl;
  struct delilah_cfg* cfg = &dpdev->ddev->cfg;
  const struct delilah_dma* dma;
  off_t pos;

  dma = entry->sqe->cmd;

  pr_debug("C2H: buf: 0x%llx len: 0x%x slot: 0x%x offset: 0x%x, op: 0x%x\n",
           dma->buf, dma->len, dma->slot, dma->offset, entry->sqe->cmd_op);

  if (!access_ok((void*)dma->buf, dma->len)) {
    pr_warn("C2H received an invalid buffer address\n");
    io_uring_cmd_done(entry->sqe, -EINVAL, -EINVAL);
    return;
  }

  chnl = xdma_get_c2h(dpdev);

  if (IS_ERR(chnl)) {
    io_uring_cmd_done(entry->sqe, -EAGAIN, -EAGAIN);
    pr_info("C2H: No channel available\n");
    return;
  }

  pos = cfg->ehdsoff + dma->slot * cfg->ehdssze;
  xdma_channel_read_write(entry->sqe, chnl, dma->buf, dma->len,
                          pos + dma->offset, 0);
  xdma_release_c2h(chnl);

  kfree(entry);

  return;
}

static irqreturn_t
ebpf_irq(int irq, void* ptr)
{
  struct delilah_pci_dev* dpdev = ptr;
  struct delilah_dev* delilah = dpdev->ddev;
  struct delilah_cmd cmd;
  uint32_t eng = irq, res;
  struct io_uring_cmd* sqe = dpdev->sqes[eng];

  memcpy_fromio(&cmd.res, &delilah->cmds[eng].res, sizeof(cmd.res));

  switch (cmd.res.status & 0x3) {
    case DELILAH_SUCCESS:
      res = cmd.res.status;
      break;

    case DELILAH_INVALID_ARGUMENT:
      dev_err(&delilah->dev, "Invalid argument (does the slot exist?)");
      res = -EINVAL;
      break;

    case DELILAH_EBPF_ERROR:
      dev_err(&delilah->dev, "eBPF execution error\n");
      res = -ENOEXEC;
      break;

    case DELILAH_INV_OPCODE:
      dev_err(&delilah->dev, "Invalid opcode");
      res = -EINVAL;
      break;

    default:
      dev_err(&delilah->dev, "Unexpected command status: 0x%x\n",
              delilah->cmds[eng].res.status);
      res = -EIO;
      break;
  }

  io_uring_cmd_done(sqe, res, res);

  return IRQ_HANDLED;
}

long
delilah_download_program(struct delilah_env* env, struct io_uring_cmd* sqe)
{
  const struct delilah_dma* dma = sqe->cmd;
  struct delilah_pci_dev* dpdev = env->delilah->dpdev;
  struct delilah_cfg* cfg = &dpdev->ddev->cfg;
  struct delilah_queue_entry* entry;

  if (dma->len > cfg->ehpssze - dma->offset) {
    dev_err(&env->delilah->dev,
            "Program size greater than program slot size: 0x%x > 0x%llx\n",
            dma->len, cfg->ehpssze);
    return -EINVAL;
  }

  if (dma->slot > cfg->ehpslot)
    return -EINVAL;

  dpdev->ehpslen[dma->slot] = dma->len;

  entry = kmalloc(sizeof(struct delilah_queue_entry), GFP_KERNEL);
  entry->sqe = sqe;
  entry->env = env;
  entry->dpdev = dpdev;

  INIT_WORK(&entry->work, work_h2c);
  queue_work(dpdev->h2c_queue, &entry->work);

  return -EIOCBQUEUED;
}

long
delilah_io(struct delilah_env* env, struct io_uring_cmd* sqe, bool write)
{
  const struct delilah_dma* dma = sqe->cmd;
  struct delilah_pci_dev* dpdev = env->delilah->dpdev;
  struct delilah_cfg* cfg = &dpdev->ddev->cfg;
  struct delilah_queue_entry* entry;

  if (dma->len > cfg->ehdssze - dma->offset) {
    dev_err(&env->delilah->dev,
            "Data size greater than data slot size: 0x%x > 0x%llx\n", dma->len,
            cfg->ehdssze);
    return -EINVAL;
  }

  if (dma->slot > cfg->ehdslot)
    return -EINVAL;

  entry = kmalloc(sizeof(struct delilah_queue_entry), GFP_KERNEL);
  entry->sqe = sqe;
  entry->env = env;
  entry->dpdev = dpdev;

  if (sqe->cmd_op == DELILAH_OP_DATA_READ) {
    INIT_WORK(&entry->work, work_c2h);
    queue_work(dpdev->c2h_queue, &entry->work);
  } else {
    INIT_WORK(&entry->work, work_h2c);
    queue_work(dpdev->h2c_queue, &entry->work);
  }

  return -EIOCBQUEUED;
}

long
delilah_exec_program(struct delilah_env* env, struct io_uring_cmd* sqe)
{
  const struct delilah_exec* exec = sqe->cmd;
  struct delilah_pci_dev* dpdev = env->delilah->dpdev;
  struct delilah_cmd cmd = {
      .req =
          {
              .opcode = sqe->cmd_op == DELILAH_OP_PROG_EXEC ? DELILAH_OPCODE_RUN_PROG : DELILAH_OPCODE_RUN_PROG_JIT,
              .cid = env->cid++,
              .run_prog.prog_slot = exec->prog_slot,
              .run_prog.data_slot = exec->data_slot,
              .run_prog.prog_len = dpdev->ehpslen[exec->prog_slot],
              .run_prog.invalidation_size = exec->invalidation_size,
              .run_prog.invalidation_offset = exec->invalidation_offset,
              .run_prog.flush_size = exec->flush_size,
              .run_prog.flush_offset = exec->flush_offset,
          },
  };
  int eng = exec->eng;

  if (exec->prog_slot < 0) {
    dev_err(&env->delilah->dev,
            "Program has not been downloaded to device. Aborting.\n");
    return -EBADFD;
  }

  if (exec->data_slot < 0) {
    dev_err(&env->delilah->dev,
            "No data has been transferred to device. Aborting.\n");
    return -EBADFD;
  }

  pr_debug("opcode: 0x%x cid: 0x%x prog_slot: 0x%x data_slot: 0x%x eng 0x%x\n",
           cmd.req.opcode, cmd.req.cid, cmd.req.run_prog.prog_slot,
           cmd.req.run_prog.data_slot, eng);

  dpdev->sqes[eng] = (struct io_uring_cmd*)sqe;

  memcpy_toio(&env->delilah->cmds[eng].req, &cmd.req, sizeof(cmd.req));
  iowrite8(1, &env->delilah->cmds_ctrl[eng].ehcmdexec);

  return -EIOCBQUEUED;
}

long
delilah_clear_cache(struct delilah_env* env, struct io_uring_cmd* sqe)
{
  const struct delilah_clear_cache* clear_cache = sqe->cmd;
  struct delilah_pci_dev* dpdev = env->delilah->dpdev;
  struct delilah_cmd cmd;
  int eng;

  cmd.req.opcode = DELILAH_OPCODE_CLEAR_CACHE;
  cmd.req.cid = env->cid++;
  eng = clear_cache->eng;

  pr_debug("opcode: 0x%x cid: 0x%x\n", cmd.req.opcode, cmd.req.cid);

  dpdev->sqes[eng] = (struct io_uring_cmd*)sqe;

  memcpy_toio(&env->delilah->cmds[eng].req, &cmd.req, sizeof(cmd.req));
  iowrite8(1, &env->delilah->cmds_ctrl[eng].ehcmdexec);

  return -EIOCBQUEUED;
}

long
delilah_clear_state(struct delilah_env* env, struct io_uring_cmd* sqe)
{
  const struct delilah_clear_state* clear_state = sqe->cmd;
  struct delilah_pci_dev* dpdev = env->delilah->dpdev;
  struct delilah_cmd cmd;
  int eng;

  cmd.req.opcode = DELILAH_OPCODE_CLEAR_STATE;
  cmd.req.cid = env->cid++;
  eng = clear_state->eng;

  pr_debug("opcode: 0x%x cid: 0x%x\n", cmd.req.opcode, cmd.req.cid);

  dpdev->sqes[eng] = (struct io_uring_cmd*)sqe;

  memcpy_toio(&env->delilah->cmds[eng].req, &cmd.req, sizeof(cmd.req));
  iowrite8(1, &env->delilah->cmds_ctrl[eng].ehcmdexec);

  return -EIOCBQUEUED;
}

long
delilah_info(struct delilah_env* env, struct io_uring_cmd* sqe)
{
  struct delilah_device info = { .ehver = env->delilah->cfg.ehver,
                                 .eheng = env->delilah->cfg.eheng,
                                 .ehpslot = env->delilah->cfg.ehpslot,
                                 .ehdslot = env->delilah->cfg.ehdslot,
                                 .ehpssze = env->delilah->cfg.ehpssze,
                                 .ehdssze = env->delilah->cfg.ehdssze,
                                 .ehsssze = env->delilah->cfg.ehsssze };

  const uint64_t* ptr = sqe->cmd;
  long b = copy_to_user(*ptr, &info, sizeof(struct delilah_device));
  io_uring_cmd_done(sqe, b, b);
  return -EIOCBQUEUED;
}

static void
dpdev_free(struct delilah_pci_dev* dpdev)
{
  struct xdma_dev* xdev = dpdev->xdev;

  ida_destroy(&dpdev->c2h_ida_wq.ida);
  ida_destroy(&dpdev->h2c_ida_wq.ida);
  ida_destroy(&dpdev->ddev->ebpf_engines_ida_wq.ida);

  dpdev->xdev = NULL;
  pr_info("dpdev 0x%p, xdev 0x%p xdma_device_close.\n", dpdev, xdev);
  xdma_device_close(dpdev->pdev, xdev);
  dpdev_cnt--;

  kfree(dpdev);
}

static struct delilah_pci_dev*
dpdev_alloc(struct pci_dev* pdev)
{
  struct delilah_pci_dev* dpdev = kmalloc(sizeof(*dpdev), GFP_KERNEL);

  if (!dpdev)
    return NULL;
  memset(dpdev, 0, sizeof(*dpdev));

  dpdev->magic = MAGIC_DEVICE;
  dpdev->pdev = pdev;
  dpdev->h2c_channel_max = XDMA_CHANNEL_NUM_MAX;
  dpdev->c2h_channel_max = XDMA_CHANNEL_NUM_MAX;

  dpdev_cnt++;
  return dpdev;
}

static void
init_ida_wq(struct ida_wq* ida_wq, unsigned int max)
{
  ida_init(&ida_wq->ida);
  ida_wq->max = max;
  init_waitqueue_head(&ida_wq->wq);
}

static int
probe_one(struct pci_dev* pdev, const struct pci_device_id* id)
{
  int rv = 0;
  struct delilah_pci_dev* dpdev = NULL;
  struct xdma_dev* xdev;
  void* hndl;
  int max_user_irqs = 4;

  dpdev = dpdev_alloc(pdev);
  if (!dpdev)
    return -ENOMEM;

  hndl = xdma_device_open(DRV_MODULE_NAME, pdev, &max_user_irqs,
                          &dpdev->h2c_channel_max, &dpdev->c2h_channel_max);
  if (!hndl) {
    rv = -EINVAL;
    goto err_out;
  }

  if (dpdev->h2c_channel_max > XDMA_CHANNEL_NUM_MAX) {
    pr_err("Maximun H2C channel limit reached\n");
    rv = -EINVAL;
    goto err_out;
  }

  if (dpdev->c2h_channel_max > XDMA_CHANNEL_NUM_MAX) {
    pr_err("Maximun C2H channel limit reached\n");
    rv = -EINVAL;
    goto err_out;
  }

  if (!dpdev->h2c_channel_max && !dpdev->c2h_channel_max)
    pr_warn("NO engine found!\n");

  /* make sure no duplicate */
  xdev = xdev_find_by_pdev(pdev);
  if (!xdev) {
    pr_warn("NO xdev found!\n");
    rv = -EINVAL;
    goto err_out;
  }

  if (hndl != xdev) {
    pr_err("xdev handle mismatch\n");
    rv = -EINVAL;
    goto err_out;
  }

  pr_info("%s xdma%d, pdev 0x%p, xdev 0x%p, 0x%p, ch %d,%d.\n",
          dev_name(&pdev->dev), xdev->idx, pdev, dpdev, xdev,
          dpdev->h2c_channel_max, dpdev->c2h_channel_max);

  dpdev->xdev = hndl;

  rv = dpdev_init_channels(dpdev);
  if (rv)
    goto err_out;

  rv = delilah_cdev_create(dpdev);
  if (rv)
    goto err_out;

  init_ida_wq(&dpdev->c2h_ida_wq, dpdev->c2h_channel_max - 1);
  init_ida_wq(&dpdev->h2c_ida_wq, dpdev->h2c_channel_max - 1);
  init_ida_wq(&dpdev->ddev->ebpf_engines_ida_wq, dpdev->ddev->cfg.eheng);

  dev_set_drvdata(&pdev->dev, dpdev);

  xdma_user_isr_enable(xdev, ~0);
  xdma_user_isr_register(xdev, ~0, ebpf_irq, dpdev);

  dpdev->h2c_queue =
    alloc_workqueue("delilah_h2c", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
  dpdev->c2h_queue =
    alloc_workqueue("delilah_c2h", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);

  if (rv)
    goto err_out;

  return 0;

err_out:
  pr_err("pdev 0x%p, err %d.\n", pdev, rv);
  dpdev_free(dpdev);
  return rv;
}

static void
remove_one(struct pci_dev* pdev)
{
  struct delilah_pci_dev* dpdev;

  if (!pdev)
    return;

  dpdev = dev_get_drvdata(&pdev->dev);
  if (!dpdev)
    return;

  flush_workqueue(dpdev->h2c_queue);
  destroy_workqueue(dpdev->h2c_queue);

  flush_workqueue(dpdev->c2h_queue);
  destroy_workqueue(dpdev->c2h_queue);

  delilah_cdev_destroy(dpdev);
  pr_info("pdev 0x%p, xdev 0x%p, 0x%p.\n", pdev, dpdev, dpdev->xdev);

  dpdev_free(dpdev);

  dev_set_drvdata(&pdev->dev, NULL);
}

static pci_ers_result_t
xdma_error_detected(struct pci_dev* pdev, pci_channel_state_t state)
{
  struct delilah_pci_dev* dpdev = dev_get_drvdata(&pdev->dev);

  switch (state) {
    case pci_channel_io_normal:
      return PCI_ERS_RESULT_CAN_RECOVER;
    case pci_channel_io_frozen:
      pr_warn("dev 0x%p,0x%p, frozen state error, reset controller\n", pdev,
              dpdev);
      xdma_device_offline(pdev, dpdev->xdev);
      pci_disable_device(pdev);
      return PCI_ERS_RESULT_NEED_RESET;
    case pci_channel_io_perm_failure:
      pr_warn("dev 0x%p,0x%p, failure state error, req. disconnect\n", pdev,
              dpdev);
      return PCI_ERS_RESULT_DISCONNECT;
  }
  return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t
xdma_slot_reset(struct pci_dev* pdev)
{
  struct delilah_pci_dev* dpdev = dev_get_drvdata(&pdev->dev);

  pr_info("0x%p restart after slot reset\n", dpdev);
  if (pci_enable_device_mem(pdev)) {
    pr_info("0x%p failed to renable after slot reset\n", dpdev);
    return PCI_ERS_RESULT_DISCONNECT;
  }

  pci_set_master(pdev);
  pci_restore_state(pdev);
  pci_save_state(pdev);
  xdma_device_online(pdev, dpdev->xdev);

  return PCI_ERS_RESULT_RECOVERED;
}

static void
xdma_error_resume(struct pci_dev* pdev)
{
  struct delilah_pci_dev* dpdev = dev_get_drvdata(&pdev->dev);

  pr_info("dev 0x%p,0x%p.\n", pdev, dpdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
  pci_cleanup_aer_uncorrect_error_status(pdev);
#else
  pci_aer_clear_nonfatal_status(pdev);
#endif
}

static int
__ida_wq_get(struct ida_wq* ida_wq, int* id)
{
  int ret;

  ret = ida_alloc_max(&ida_wq->ida, ida_wq->max, GFP_KERNEL);
  if (ret == -ENOSPC)
    return 0;
  *id = ret;
  return 1;
}

static int
ida_wq_get(struct ida_wq* ida_wq)
{
  int id, ret;

  ret = wait_event_interruptible(ida_wq->wq, __ida_wq_get(ida_wq, &id));
  if (ret)
    return ret;

  return id;
}

static void
ida_wq_release(struct ida_wq* ida_wq, unsigned int id)
{
  ida_free(&ida_wq->ida, id);
  wake_up_interruptible(&ida_wq->wq);
}

static const struct pci_error_handlers xdma_err_handler = {
  .error_detected = xdma_error_detected,
  .slot_reset = xdma_slot_reset,
  .resume = xdma_error_resume,
};

static inline struct xdma_channel*
xdma_get_chnl(struct xdma_channel* channels, struct ida_wq* ida_wq)
{
  int id = ida_wq_get(ida_wq);
  if (id < 0)
    return ERR_PTR(id);
  return &channels[id];
}

struct xdma_channel*
xdma_get_c2h(struct delilah_pci_dev* dpdev)
{
  return xdma_get_chnl(dpdev->xdma_c2h_chnl, &dpdev->c2h_ida_wq);
}

struct xdma_channel*
xdma_get_h2c(struct delilah_pci_dev* dpdev)
{
  return xdma_get_chnl(dpdev->xdma_h2c_chnl, &dpdev->h2c_ida_wq);
}

void
xdma_release_c2h(struct xdma_channel* chnl)
{
  unsigned int id = chnl->engine->channel;
  struct delilah_pci_dev* dpdev;

  dpdev = container_of(chnl, struct delilah_pci_dev, xdma_c2h_chnl[id]);
  ida_wq_release(&dpdev->c2h_ida_wq, id);
}

void
xdma_release_h2c(struct xdma_channel* chnl)
{
  unsigned int id = chnl->engine->channel;
  struct delilah_pci_dev* dpdev;

  dpdev = container_of(chnl, struct delilah_pci_dev, xdma_h2c_chnl[id]);
  ida_wq_release(&dpdev->h2c_ida_wq, id);
}

static struct pci_driver pci_driver = {
  .name = DRV_MODULE_NAME,
  .id_table = pci_ids,
  .probe = probe_one,
  .remove = remove_one,
  .err_handler = &xdma_err_handler,
};

static int __init
delilah_mod_init(void)
{
  int rv;
  pr_info("%s", version);

  rv = delilah_cdev_init();
  if (rv < 0)
    return rv;

  return pci_register_driver(&pci_driver);
}

static void __exit
delilah_mod_exit(void)
{
  /* unregister this driver from the PCI bus driver */
  pr_debug("pci_unregister_driver.\n");
  pci_unregister_driver(&pci_driver);
  delilah_cdev_cleanup();
}

module_init(delilah_mod_init);
module_exit(delilah_mod_exit);
