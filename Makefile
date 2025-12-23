# KVM Probe Framework Makefile
# Builds kernel module and userspace tool

# Kernel module
obj-m += kvm_probe_drv.o
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KBUILD_CFLAGS += -Wno-error

# Userspace tool
CC = gcc
CFLAGS = -Wno-error -O2 -g

.PHONY: all module userspace clean install uninstall help

all: module userspace

module:
	@echo "[*] Building kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

userspace: probe
	@echo "[+] Userspace tool built"

probe: kvm_prober.c
	@echo "[*] Building userspace tool..."
	$(CC) $(CFLAGS) -o probe kvm_prober.c

clean:
	@echo "[*] Cleaning..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f probe

install: module
	@echo "[*] Installing module..."
	sudo insmod kvm_probe_drv.ko
	@echo "[+] Module loaded"
	@ls -la /dev/kvm_probe_dev 2>/dev/null || echo "[-] Device not created"

uninstall:
	@echo "[*] Unloading module..."
	-sudo rmmod kvm_probe_drv
	@echo "[+] Module unloaded"

reload: uninstall install

test: install userspace
	@echo "[*] Running quick test..."
	./probe count
	./probe vmx
	./probe kaslr

help:
	@echo "KVM Probe Framework Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build kernel module and userspace tool"
	@echo "  module    - Build only the kernel module"
	@echo "  userspace - Build only the userspace tool"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Load the kernel module"
	@echo "  uninstall - Unload the kernel module"
	@echo "  reload    - Unload and reload module"
	@echo "  test      - Install and run quick test"
	@echo ""
	@echo "Usage:"
	@echo "  make                  # Build everything"
	@echo "  sudo make install     # Load module"
	@echo "  ./probe help          # Show tool usage"