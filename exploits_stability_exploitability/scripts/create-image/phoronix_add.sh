#!/bin/bash

mount -o loop ./stretch.img ./rootfs
rm -rf ./rootfs/var/lib/phoronix-test-suite/installed-tests/pts/
cp -r ./pts ./rootfs/var/lib/phoronix-test-suite/installed-tests/
umount ./rootfs