# Amazon FPGA Hardware Development Kit
#
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#    http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

SHELL = /bin/bash

topdir := $(shell cd $(src)/.. && pwd)

TARGET_MODULE:=delilah

EXTRA_CFLAGS := -I$(topdir)/include
EXTRA_CFLAGS += -D__LIBXDMA_DEBUG__
EXTRA_CFLAGS += -DDebug

ifneq ($(KERNELRELEASE),)
	$(TARGET_MODULE)-objs := xdma/libxdma.o xdma/xdma_thread.o xdma_sgdma.o delilah_mod.o delilah_cdev.o
	obj-m := $(TARGET_MODULE).o
else
	BUILDSYSTEM_DIR:=/lib/modules/$(shell uname -r)/build
	PWD:=$(shell pwd)
all :
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean
	@/bin/rm -f *.ko modules.order *.mod.c *.o *.o.ur-safe .*.o.cmd

install: all
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules_install
	depmod -a
	install -m 644 10-delilah.rules /etc/udev/rules.d
	-rmmod -s delilah || true
	-modprobe delilah

uninstall:
	-rm -f /etc/udev/rules.d/10-delilah.rules
	-rmmod -s delilah || true
	-rm -f /lib/modules/`uname -r`/extra/delilah.ko
	depmod -a

# Allow make install and uninstall targets to work without having to set ec2 in the environment.
noop:

endif

ifneq ($(ec2),1)
	CFLAGS_delilah_mod.o := -DINTERNAL_TESTING
endif
