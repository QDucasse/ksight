PWD := $(shell pwd)

obj-m := ksight.o
PL ?=

ARCH := arm64

KDIR := $(PL)/build/tmp/work/xilinx_zcu104-xilinx-linux/linux-xlnx/6.1.5-xilinx-v2023.1+gitAUTOINC+716921b6d7-r0/linux-xilinx_zcu104-standard-build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
