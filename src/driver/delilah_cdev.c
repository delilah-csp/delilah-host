/*******************************************************************************
 *
 * Delilah Linux Driver
 * Copyright(c) 2020 Eideticom, Inc.
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

#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "delilah_mod.h"
#include "xdma_sgdma.h"

#define DELILAH_MINOR_BASE 0
#define DELILAH_MINOR_COUNT 16
#define DELILAH_NAME "delilah"

#define DELILAH_CMDREQ_BASE 0x1000
#define DELILAH_CMDCTRL_BASE 0x2000

#define DELILAH_EXEC_RING_SIZE 1024
#define DELILAH_DMA_RING_SIZE 1024

static struct class* delilah_class;
DEFINE_IDA(delilah_ida);
static dev_t delilah_devt;

static int
delilah_open(struct inode* inode, struct file* filp)
{
  struct delilah_dev* delilah;
  struct delilah_env* env;

  delilah = container_of(inode->i_cdev, struct delilah_dev, cdev);
  env = kzalloc(sizeof(*env), GFP_KERNEL);
  env->delilah = delilah;
  env->cid = 0;
  filp->private_data = env;

  return 0;
}

static int
delilah_close(struct inode* inode, struct file* filp)
{
  struct delilah_env* env = filp->private_data;

  kfree(env);

  return 0;
}

static int
delilah_uring_cmd(struct io_uring_cmd* sqe, unsigned int res)
{
  struct delilah_env* env = sqe->file->private_data;
  switch (sqe->cmd_op) {
    case DELILAH_OP_PROG_EXEC:
    case DELILAH_OP_PROG_EXEC_JIT:
      return delilah_exec_program(env, sqe);
    case DELILAH_OP_PROG_WRITE:
      return delilah_download_program(env, sqe);
    case DELILAH_OP_DATA_READ:
      return delilah_io(env, sqe, 0);
    case DELILAH_OP_DATA_WRITE:
      return delilah_io(env, sqe, 1);
    case DELILAH_OP_CLEAR_CACHE:
      return delilah_clear_cache(env, sqe);
  }

  return -EINVAL;
}

static const struct file_operations delilah_fops = { .owner = THIS_MODULE,
                                                     .open = delilah_open,
                                                     .release = delilah_close,
                                                     .uring_cmd =
                                                       delilah_uring_cmd };

static struct delilah_dev*
to_delilah(struct device* dev)
{
  return container_of(dev, struct delilah_dev, dev);
}

static void
delilah_release(struct device* dev)
{
  struct delilah_dev* delilah = to_delilah(dev);

  kfree(delilah);
}

static int
delilah_read_cfg(struct delilah_pci_dev* dpdev)
{
  struct delilah_cfg* cfg;
  void __iomem* bar0 = pci_iomap(dpdev->pdev, 0, sizeof(*cfg));
  if (!bar0)
    return -EFAULT;

  cfg = &dpdev->ddev->cfg;

  memcpy_fromio(cfg, bar0, sizeof(*cfg));
  pr_info("ehver: 0x%x ehbld: %s eheng: 0x%x ehpslot: 0x%x ehdslot: 0x%x "
          "ehpsoff: 0x%llx ehpssze: 0x%llx ehdsoff: 0x%llx ehdssze: 0x%llx\n",
          cfg->ehver, cfg->ehbld, cfg->eheng, cfg->ehpslot, cfg->ehdslot,
          cfg->ehpsoff, cfg->ehpssze, cfg->ehdsoff, cfg->ehdssze);
  return 0;
}

static int
delilah_set_cmd_regs(struct delilah_pci_dev* dpdev)
{
  void __iomem* bar0 =
    pci_iomap(dpdev->pdev, 0,
              DELILAH_CMDCTRL_BASE +
                dpdev->ddev->cfg.eheng * sizeof(struct delilah_cmd_ctrl));
  if (!bar0)
    return -EFAULT;

  dpdev->ddev->cmds = bar0 + DELILAH_CMDREQ_BASE;
  dpdev->ddev->cmds_ctrl = bar0 + DELILAH_CMDCTRL_BASE;

  return 0;
}

int
delilah_cdev_create(struct delilah_pci_dev* dpdev)
{
  struct pci_dev* pdev = dpdev->pdev;
  struct delilah_dev* delilah;
  int err;

  delilah = kzalloc(sizeof(*delilah), GFP_KERNEL);
  if (!delilah)
    return -ENOMEM;

  dpdev->ddev = delilah;
  delilah->pdev = pdev;
  delilah->dpdev = dpdev;

  err = delilah_read_cfg(dpdev);
  if (err)
    goto out_free;
  err = delilah_set_cmd_regs(dpdev);
  if (err)
    goto out_free;

  device_initialize(&delilah->dev);
  delilah->dev.class = delilah_class;
  delilah->dev.parent = &pdev->dev;
  delilah->dev.release = delilah_release;

  delilah->id = ida_simple_get(&delilah_ida, 0, 0, GFP_KERNEL);
  if (delilah->id < 0) {
    err = delilah->id;
    goto out_free;
  }

  dev_set_name(&delilah->dev, "delilah%d", delilah->id);
  delilah->dev.devt = MKDEV(MAJOR(delilah_devt), delilah->id);

  cdev_init(&delilah->cdev, &delilah_fops);
  delilah->cdev.owner = THIS_MODULE;
  err = cdev_device_add(&delilah->cdev, &delilah->dev);
  if (err)
    goto out_ida;

  ida_init(&delilah->prog_slots);
  ida_init(&delilah->data_slots);

  dev_info(&delilah->dev, "device created");

  return 0;

out_ida:
  ida_simple_remove(&delilah_ida, delilah->id);
out_free:
  kfree(delilah);
  return err;
}

void
delilah_cdev_destroy(struct delilah_pci_dev* dpdev)
{
  struct delilah_dev* delilah = dpdev->ddev;

  dev_info(&delilah->dev, "device removed");

  cdev_device_del(&delilah->cdev, &delilah->dev);
  ida_simple_remove(&delilah_ida, delilah->id);
  ida_destroy(&delilah->prog_slots);
  ida_destroy(&delilah->data_slots);
  put_device(&delilah->dev);
}

int
delilah_cdev_init(void)
{
  int rc;

  delilah_class = class_create(THIS_MODULE, DELILAH_NAME);
  if (IS_ERR(delilah_class))
    return PTR_ERR(delilah_class);

  rc = alloc_chrdev_region(&delilah_devt, DELILAH_MINOR_BASE,
                           DELILAH_MINOR_COUNT, DELILAH_NAME);

  if (rc)
    goto err_class;

  return rc;

err_class:
  class_destroy(delilah_class);
  return rc;
}

void
delilah_cdev_cleanup(void)
{
  unregister_chrdev_region(delilah_devt, DELILAH_MINOR_COUNT);
  class_destroy(delilah_class);
}
