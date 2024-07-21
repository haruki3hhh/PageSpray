Installing phoronix test suites inside docker + qemu is super annoying because they're platform specific.
So here's how to do it inside a docker container:
- copy the temporary `pts` folder here into the image with `phoronix_add.sh`
- launch qemu with `startvm` from any CVE folder
- run `phoronix-test-suite install pts/apache-1.7.2` inside qemu
- open another shell in the same docker container, run `phoronix_update.sh`