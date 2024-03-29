/*******************************************************************************
 *
 * Delilah Linux Driver
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

#ifndef DELILAH_H
#define DELILAH_H

#include <linux/types.h>

enum delilah_ops
{
  DELILAH_OP_PROG_EXEC,
  DELILAH_OP_PROG_WRITE,
  DELILAH_OP_DATA_READ,
  DELILAH_OP_DATA_WRITE,
  DELILAH_OP_PROG_EXEC_JIT,
  DELILAH_OP_CLEAR_CACHE,
  DELILAH_OP_INFO,
  DELILAH_OP_CLEAR_STATE,
};

struct delilah_exec
{
  __u8 eng;
  __u8 prog_slot;
  __u8 data_slot;

  __u32 invalidation_size;
  __u32 invalidation_offset;
  __u32 flush_size;
  __u32 flush_offset;
};

struct delilah_clear_cache
{
  __u8 eng;
};

struct delilah_clear_state
{
  __u8 eng;
  __u64 size;
  __u64 offset;
};

struct delilah_dma
{
  __u64 buf;
  __u32 len;
  __u32 offset;
  __u8 slot;
};

struct delilah_device
{
  __u32 ehver;
  __u8 eheng;
  __u8 ehpslot;
  __u8 ehdslot;
  __u64 ehpssze;
  __u64 ehdssze;
  __u64 ehsssze;
};

#endif // DELILAH_H
