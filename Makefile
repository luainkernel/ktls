# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the TLS subsystem.
#

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=${PWD} CONFIG_LUNATIK=m CONFIG_KTLS=m
	gcc -o test test.c -lgnutls -lpthread
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm test
