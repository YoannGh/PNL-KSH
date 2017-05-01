.PHONY: all 
#.SECONDARY:
ifneq ($(KERNELRELEASE),)
  
  obj-m := ksh.o
  $(info obj-m: $(obj-m))
else
	
  KERNELDIR = /tmp/linux-4.2.3
  PWD := $(shell pwd)
  $(info KERNELDIR: $(KERNELDIR))
  $(info PWD: $(PWD))

all :
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

endif
