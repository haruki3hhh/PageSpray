# Take a Step Further: Understanding Page Spray in Linux Kernel Exploitation
Page Spray is a kernel exploitation technique which utilizes Direct Page Allocation and Copy/Remap/Write in kernel to perform page reclaim from Page Allocator and spray evil/crafted data to pages. Page Spray(**"DirtyPage"**) has multiple variants, and can be data-only attack.

**Paper Link:** https://arxiv.org/abs/2406.02624

**BlackHat USA 2023 Link:** [Bad io_uring: A New Era of Rooting for Android](https://www.blackhat.com/us-23/briefings/schedule/index.html#bad-io_uring-a-new-era-of-rooting-for-android-32243)

**Google kCTF and TyphoonPWN:** [LINUX CLOCK_THREAD_CPUTIME_ID LPE](https://ssd-disclosure.com/ssd-advisory-linux-clock_thread_cputime_id-lpe/)
