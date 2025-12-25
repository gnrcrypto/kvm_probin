 #!/bin/bash

make KCFLAGS="-Wno-error"
make KCFLAGS="-Wno-error" install
make kvm_prober
make hyperdump
cp kvm_prober /bin
cp hyperdump /bin
chmod +x exploit.sh
./exploit.sh
