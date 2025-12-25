#!/bin/bash

make KCFLAGS="-Wno-error"
make KCFLAGS="-Wno-error" install
make kvm_prober
cp kvm_prober /bin
chmod +x exploit.sh
./exploit.sh
