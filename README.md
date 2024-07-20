# Take a Step Further: Understanding Page Spray in Linux Kernel Exploitation
***
Authors: 

[Ziyi Guo](http://ziyiguo.site/), [Dang K Le](https://lkmidas.github.io/about/), [Zhenpeng Lin](https://zplin.me/), [Kyle Zeng](https://www.kylebot.net/), [Ruoyu Wang](https://ruoyuwang.me/), [Tiffany Bao](https://www.tiffanybao.com/), [Yan Shoshitaishvili](https://yancomm.net/), [Adam Doupé](https://adamdoupe.com/), [Xinyu Xing](http://xinyuxing.org/)
***
Page Spray is a kernel exploitation technique which utilizes Direct Page Allocation and Copy/Remap/Write in kernel to perform page reclaim from Page Allocator and spray evil/crafted data to pages. Page Spray(**"DirtyPage"**) has multiple variants, and can be data-only attack.

**USENIX Link:** https://www.usenix.org/conference/usenixsecurity24/presentation/guo-ziyi

**Arxiv Paper Link:** https://arxiv.org/abs/2406.02624

**BlackHat USA 2023 Link:** [Bad io_uring: A New Era of Rooting for Android](https://www.blackhat.com/us-23/briefings/schedule/index.html#bad-io_uring-a-new-era-of-rooting-for-android-32243)

**Google kCTF and TyphoonPWN Link:** [LINUX CLOCK_THREAD_CPUTIME_ID LPE](https://ssd-disclosure.com/ssd-advisory-linux-clock_thread_cputime_id-lpe/)
