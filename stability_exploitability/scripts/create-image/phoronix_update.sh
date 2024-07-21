#!/bin/bash

rm -rf ./pts
scp -P10069 -r -i /pagespray/scripts/create-image/stretch.id_rsa root@localhost:/var/lib/phoronix-test-suite/installed-tests/pts/ .
mount -o loop ./stretch.img ./rootfs
rm -rf ./rootfs/var/lib/phoronix-test-suite/installed-tests/pts/
cp -r ./pts ./rootfs/var/lib/phoronix-test-suite/installed-tests/
umount ./rootfs
