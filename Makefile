define build
	$(MAKE) -C fops $@ PWD=$(PWD)/fops
	$(MAKE) -C zero $@ PWD=$(PWD)/zero
	$(MAKE) -C xor128 $@ PWD=$(PWD)/xor128
endef

all clean test:
	$(call build)

