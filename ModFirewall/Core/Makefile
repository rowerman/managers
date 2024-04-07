obj-m += mod_firewall_pre_routing.o mod_firewall_post_routing.o mod_firewall_local_out.o mod_firewall_local_in.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
