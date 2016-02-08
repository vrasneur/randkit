obj-m += randkit_fops.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo insmod randkit_fops.ko urandom_fops_addr=0x$(shell grep urandom_fops /boot/System.map-$(shell uname -r) | cut -d' ' -f1)
	sudo rmmod randkit_fops
