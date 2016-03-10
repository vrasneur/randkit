obj-m += randkit_xor128.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo insmod randkit_xor128.ko
	head -c16 /dev/urandom | hexdump
	sudo rmmod randkit_xor128
