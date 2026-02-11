obj-m += dbg.o

# Set the path to the Kernel build utils.
KBUILD=/lib/modules/6.5.0-41-generic/build

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules
clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

