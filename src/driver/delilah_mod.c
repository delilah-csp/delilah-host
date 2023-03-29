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

#include <linux/aer.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/ioctl.h>
#include <linux/types.h>
/* include early, to verify it depends only on the headers above */
#include "delilah_mod.h"
#include "xdma/libxdma.h"
#include "xdma/libxdma_api.h"
#include "xdma/xdma_thread.h"
#include "xdma_sgdma.h"

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
MODULE_LICENSE("GPL v2");

/* SECTION: Module global variables */
static int hpdev_cnt;

static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(0x1de5, 0x3000), },
	{ PCI_DEVICE(0x1de5, 0x9038), },
	{ PCI_DEVICE(0x719e, 0x1000), },
	{0,}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static irqreturn_t
ebpf_irq(int irq, void* ptr)
{
  struct delilah_pci_dev* hpdev = ptr;
  struct delilah_dev* delilah = hpdev->hdev;
  struct delilah_cmd cmd;
  int eng = irq, res;
  struct io_uring_cmd* sqe = hpdev->sqes[eng];

  int64_t ebpf_ret;

  memcpy_fromio(&cmd.res, &delilah->cmds[eng].res, sizeof(cmd.res));

  switch (delilah->cmds[eng].res.status) {
    case DELILAH_SUCCESS:
      ebpf_ret = delilah->cmds[eng].res.ebpf_ret;
      if (ebpf_ret) {
        dev_warn(&delilah->dev,
                 "Delilah returned with status 0x%x but eBPF return 0x%llx "
                 "(expected 0)\n",
                 DELILAH_SUCCESS, ebpf_ret);
        res = -ENOEXEC;
      } else {
        res = 0;
      }
      break;

    case DELILAH_INV_PROG_SLOT:
      dev_err(&delilah->dev, "Invalid program slot");
      res = -EBADFD;
      break;

    case DELILAH_INV_DATA_SLOT:
      dev_err(&delilah->dev, "Invalid data slot");
      res = -EBADFD;
      break;

    case DELILAH_EBPF_ERROR:
      ebpf_ret = delilah->cmds[eng].res.ebpf_ret;
      dev_err(&delilah->dev, "eBPF execution error. eBPF return code: %llx\n",
              ebpf_ret);
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
delilah_download_program(struct delilah_env* env,
                         struct io_uring_cmd* sqe)
{
  const struct delilah_dma* dma = sqe->cmd;
  struct delilah_pci_dev* hpdev = env->delilah->hpdev;
  struct delilah_cfg* cfg = &hpdev->hdev->cfg;
  struct xdma_channel* chnl;
  long res;
  loff_t pos;

  if (dma->len > cfg->ehpssze) {
    dev_err(&env->delilah->dev,
            "Program size greater than program slot size: 0x%x > 0x%llx\n",
            dma->len, cfg->ehpssze);
    return -EINVAL;
  }

  if (dma->slot > cfg->ehpslot)
    return -EINVAL;

  hpdev->ehpslen[dma->slot] = dma->len;

  chnl = xdma_get_h2c(hpdev);
  if (IS_ERR(chnl))
    return PTR_ERR(chnl);

  pos = cfg->ehpsoff + dma->slot * cfg->ehpssze;

  res = xdma_channel_read_write(sqe, chnl, dma->buf, dma->len, pos, 1);

  if (res < 0)
    return res;
  else if (res != dma->len)
    return -EIO;

  return -EIOCBQUEUED;
}

long
delilah_io(struct delilah_env* env, struct io_uring_cmd* sqe, bool write)
{
  const struct delilah_dma* dma = sqe->cmd;
  struct delilah_pci_dev* hpdev = env->delilah->hpdev;
  struct delilah_cfg* cfg = &hpdev->hdev->cfg;
  struct xdma_channel* chnl;
  long res;
  loff_t pos;

  if (dma->len > cfg->ehdssze) {
    dev_err(&env->delilah->dev,
            "Data size greater than data slot size: 0x%x > 0x%llx\n", dma->len,
            cfg->ehdssze);
    return -EINVAL;
  }

  if (dma->slot > cfg->ehdslot)
    return -EINVAL;

  chnl =
    write ? xdma_get_h2c(hpdev) : xdma_get_c2h(hpdev);
  if (IS_ERR(chnl))
    return PTR_ERR(chnl);

  pos = cfg->ehdsoff + dma->slot * cfg->ehdssze;

  res = xdma_channel_read_write(sqe, chnl, dma->buf, dma->len, pos, write);

  if (res < 0)
    return res;
  else if (res != dma->len)
    return -EIO;

  return -EIOCBQUEUED;
}

long
delilah_exec_program(struct delilah_env* env, struct io_uring_cmd* sqe)
{
  const struct delilah_exec* exec = sqe->cmd;
  struct delilah_pci_dev* hpdev = env->delilah->hpdev;
  struct delilah_cmd cmd = {
      .req =
          {
              .opcode = sqe->cmd_op == DELILAH_OP_PROG_EXEC ? DELILAH_OPCODE_RUN_PROG : DELILAH_OPCODE_RUN_PROG_JIT,
              .cid = env->cid++,
              .prog_slot = exec->prog_slot,
              .data_slot = exec->data_slot,
              .prog_len = hpdev->ehpslen[exec->prog_slot],
              .invalidation_size = exec->invalidation_size,
              .invalidation_offset = exec->invalidation_offset,
              .flush_size = exec->flush_size,
              .flush_offset = exec->flush_offset,
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

  pr_debug("opcode: 0x%x cid: 0x%x prog_slot: 0x%x data_slot: 0x%x\n",
           cmd.req.opcode, cmd.req.cid, cmd.req.prog_slot, cmd.req.data_slot);

  hpdev->sqes[eng] = (struct io_uring_cmd*)sqe;

  memcpy_toio(&env->delilah->cmds[eng].req, &cmd.req, sizeof(cmd.req));
  iowrite8(1, &env->delilah->cmds_ctrl[eng].ehcmdexec);

  return -EIOCBQUEUED;
}

static void
hpdev_free(struct delilah_pci_dev* hpdev)
{
  struct xdma_dev* xdev = hpdev->xdev;

  ida_destroy(&hpdev->c2h_ida_wq.ida);
  ida_destroy(&hpdev->h2c_ida_wq.ida);
  ida_destroy(&hpdev->hdev->ebpf_engines_ida_wq.ida);

  hpdev->xdev = NULL;
  pr_info("hpdev 0x%p, xdev 0x%p xdma_device_close.\n", hpdev, xdev);
  xdma_device_close(hpdev->pdev, xdev);
  hpdev_cnt--;

  kfree(hpdev);
}

static struct delilah_pci_dev*
hpdev_alloc(struct pci_dev* pdev)
{
  struct delilah_pci_dev* hpdev = kmalloc(sizeof(*hpdev), GFP_KERNEL);

  if (!hpdev)
    return NULL;
  memset(hpdev, 0, sizeof(*hpdev));

  hpdev->magic = MAGIC_DEVICE;
  hpdev->pdev = pdev;
  hpdev->h2c_channel_max = XDMA_CHANNEL_NUM_MAX;
  hpdev->c2h_channel_max = XDMA_CHANNEL_NUM_MAX;

  hpdev_cnt++;
  return hpdev;
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
  struct delilah_pci_dev* hpdev = NULL;
  struct xdma_dev* xdev;
  void* hndl;
  int max_user_irqs = 4;

  hpdev = hpdev_alloc(pdev);
  if (!hpdev)
    return -ENOMEM;

  hndl = xdma_device_open(DRV_MODULE_NAME, pdev, &max_user_irqs,
                          &hpdev->h2c_channel_max, &hpdev->c2h_channel_max);
  if (!hndl) {
    rv = -EINVAL;
    goto err_out;
  }

  if (hpdev->h2c_channel_max > XDMA_CHANNEL_NUM_MAX) {
    pr_err("Maximun H2C channel limit reached\n");
    rv = -EINVAL;
    goto err_out;
  }

  if (hpdev->c2h_channel_max > XDMA_CHANNEL_NUM_MAX) {
    pr_err("Maximun C2H channel limit reached\n");
    rv = -EINVAL;
    goto err_out;
  }

  if (!hpdev->h2c_channel_max && !hpdev->c2h_channel_max)
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
          dev_name(&pdev->dev), xdev->idx, pdev, hpdev, xdev,
          hpdev->h2c_channel_max, hpdev->c2h_channel_max);

  hpdev->xdev = hndl;

  rv = hpdev_init_channels(hpdev);
  if (rv)
    goto err_out;

  rv = delilah_cdev_create(hpdev);
  if (rv)
    goto err_out;

  init_ida_wq(&hpdev->c2h_ida_wq, hpdev->c2h_channel_max - 1);
  init_ida_wq(&hpdev->h2c_ida_wq, hpdev->h2c_channel_max - 1);
  init_ida_wq(&hpdev->hdev->ebpf_engines_ida_wq, hpdev->hdev->cfg.eheng);

  dev_set_drvdata(&pdev->dev, hpdev);

  xdma_user_isr_enable(xdev, ~0);
  xdma_user_isr_register(xdev, ~0, ebpf_irq, hpdev);

  return 0;

err_out:
  pr_err("pdev 0x%p, err %d.\n", pdev, rv);
  hpdev_free(hpdev);
  return rv;
}

static void
remove_one(struct pci_dev* pdev)
{
  struct delilah_pci_dev* hpdev;

  if (!pdev)
    return;

  hpdev = dev_get_drvdata(&pdev->dev);
  if (!hpdev)
    return;

  delilah_cdev_destroy(hpdev);
  pr_info("pdev 0x%p, xdev 0x%p, 0x%p.\n", pdev, hpdev, hpdev->xdev);
  hpdev_free(hpdev);

  dev_set_drvdata(&pdev->dev, NULL);
}

static pci_ers_result_t
xdma_error_detected(struct pci_dev* pdev, pci_channel_state_t state)
{
  struct delilah_pci_dev* hpdev = dev_get_drvdata(&pdev->dev);

  switch (state) {
    case pci_channel_io_normal:
      return PCI_ERS_RESULT_CAN_RECOVER;
    case pci_channel_io_frozen:
      pr_warn("dev 0x%p,0x%p, frozen state error, reset controller\n", pdev,
              hpdev);
      xdma_device_offline(pdev, hpdev->xdev);
      pci_disable_device(pdev);
      return PCI_ERS_RESULT_NEED_RESET;
    case pci_channel_io_perm_failure:
      pr_warn("dev 0x%p,0x%p, failure state error, req. disconnect\n", pdev,
              hpdev);
      return PCI_ERS_RESULT_DISCONNECT;
  }
  return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t
xdma_slot_reset(struct pci_dev* pdev)
{
  struct delilah_pci_dev* hpdev = dev_get_drvdata(&pdev->dev);

  pr_info("0x%p restart after slot reset\n", hpdev);
  if (pci_enable_device_mem(pdev)) {
    pr_info("0x%p failed to renable after slot reset\n", hpdev);
    return PCI_ERS_RESULT_DISCONNECT;
  }

  pci_set_master(pdev);
  pci_restore_state(pdev);
  pci_save_state(pdev);
  xdma_device_online(pdev, hpdev->xdev);

  return PCI_ERS_RESULT_RECOVERED;
}

static void
xdma_error_resume(struct pci_dev* pdev)
{
  struct delilah_pci_dev* hpdev = dev_get_drvdata(&pdev->dev);

  pr_info("dev 0x%p,0x%p.\n", pdev, hpdev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
  pci_cleanup_aer_uncorrect_error_status(pdev);
#else
  pci_aer_clear_nonfatal_status(pdev);
#endif
}

static int __ida_wq_get(struct ida_wq *ida_wq, int *id)
{
	int ret;

	ret = ida_alloc_max(&ida_wq->ida, ida_wq->max, GFP_KERNEL);
	if (ret == -ENOSPC)
		return 0;
	*id = ret;
	return 1;
}

static int ida_wq_get(struct ida_wq *ida_wq)
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

static inline struct xdma_channel *xdma_get_chnl(struct xdma_channel *channels,
		struct ida_wq *ida_wq)
{
	int id = ida_wq_get(ida_wq);
	if (id < 0)
		return ERR_PTR(id);
	return &channels[id];
}

struct xdma_channel *xdma_get_c2h(struct delilah_pci_dev *hpdev)
{
	return xdma_get_chnl(hpdev->xdma_c2h_chnl, &hpdev->c2h_ida_wq);
}

struct xdma_channel *xdma_get_h2c(struct delilah_pci_dev *hpdev)
{
	return xdma_get_chnl(hpdev->xdma_h2c_chnl, &hpdev->h2c_ida_wq);
}

void
xdma_release_c2h(struct xdma_channel* chnl)
{
  unsigned int id = chnl->engine->channel;
  struct delilah_pci_dev* hpdev;

  hpdev = container_of(chnl, struct delilah_pci_dev, xdma_c2h_chnl[id]);
  ida_wq_release(&hpdev->c2h_ida_wq, id);
}

void
xdma_release_h2c(struct xdma_channel* chnl)
{
  unsigned int id = chnl->engine->channel;
  struct delilah_pci_dev* hpdev;

  hpdev = container_of(chnl, struct delilah_pci_dev, xdma_h2c_chnl[id]);
  ida_wq_release(&hpdev->h2c_ida_wq, id);
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

  xdma_threads_create(16);

  return pci_register_driver(&pci_driver);
}

static void __exit
delilah_mod_exit(void)
{
  xdma_threads_destroy();
  /* unregister this driver from the PCI bus driver */
  pr_debug("pci_unregister_driver.\n");
  pci_unregister_driver(&pci_driver);
  delilah_cdev_cleanup();
}

module_init(delilah_mod_init);
module_exit(delilah_mod_exit);
