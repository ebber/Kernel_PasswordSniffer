name += sniffer_mod
obj-m += $(name).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
test:
	sudo dmesg -C
	sudo insmod $(name).ko
	sudo rmmod $(name).ko
	dmesg
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
