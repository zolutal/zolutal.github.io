var store = [{
        "title": "Understanding Memory Deduplication Attacks",
        "excerpt":"I recently came across a bunch of research describing attacks on memory deduplication, it has been used to fingerprint systems[1], crack (K)ASLR[2,3,4], leak database records[4], and even exploit rowhammer[5]. It’s a really cool class of attacks that I hadn’t heard of before, but I wasn’t having much luck finding any...","categories": [],
        "tags": ["Exploitation","Sidechannels","Linux","KVM","KASLR"],
        "url": "/dedup-attacks/",
        "teaser": null
      },{
        "title": "corCTF 2023: sysruption writeup",
        "excerpt":"I played corCTF this weekend and managed to solve two pretty tough challenges. This will be a writeup for the first of those two, sysruption, which I managed to get first-blood on! As described by the challenge text, sysruption is about: A hardware quirk, a micro-architecture attack, and a kernel...","categories": [],
        "tags": ["Exploitation","Sidechannels","Linux","CTF Writeup"],
        "url": "/corctf-sysruption/",
        "teaser": null
      },{
        "title": "Understanding x86_64 Paging",
        "excerpt":"I’ve spent quite a lot of time messing with x86_64 page tables, understanding address translation is not easy and when I started learning about it I felt like a lot of the material out there on how it works was hard for me to wrap my head around. So in...","categories": [],
        "tags": ["x86_64","Linux","Architecture"],
        "url": "/understanding-paging/",
        "teaser": null
      },{
        "title": "ASLRn't: How memory alignment broke library ASLR",
        "excerpt":"As it turns out, on recent Ubuntu, Arch, Fedora, and likely other distro’s releases, with kernel versions &gt;=5.18, library ASLR is literally broken for 32-bit libraries of at least 2MB in size, on certain filesystems. Also, ASLR’s entropy on 64-bit libraries that are at least 2MB is significantly reduced, 28...","categories": [],
        "tags": ["Linux","ASLR","x86_64"],
        "url": "/aslrnt/",
        "teaser": null
      },{
        "title": "corCTF 2024: trojan-turtles writeup",
        "excerpt":"This year I played corCTF with Shellphish, and we did pretty well – placing 6th! I worked on two challenges: ‘trojan-turtles’ and ‘its-just-a-dos-bug-bro’, in the end we solved both of them and both only had two solves by the end. This will be a writeup for ‘trojan-turtles’, a challenge which...","categories": [],
        "tags": ["Exploitation","Sidechannels","x86_64","Architecture","Linux","CTF Writeup"],
        "url": "/corctf-trojan-turtles/",
        "teaser": null
      },{
        "title": "The Joys of Linux Kernel ROP Gadget Scanning",
        "excerpt":"Linux Kernel ROP gadget scanning is one of those things that seems easy in theory – just run ROPgadget --binary vmlinux on it! In practice, however, anyone who has used that method has likely had to sift through a large amount of false positives and likely missed some gadgets due...","categories": [],
        "tags": ["Exploitation","Linux"],
        "url": "/joys-of-kernel-rop/",
        "teaser": null
      },{
        "title": "Securinets Quals 2025: Sukunahikona (v8 Exploitation)",
        "excerpt":"I played Securinets Quals this weekend with Shellphish; we ended up placing 7th, qualifying us for finals! When I logged on to play, all of the released pwn was already solved or close to solved by @vy, except for the v8 challenge. Despite having never touched v8 pwn before, I...","categories": [],
        "tags": ["Exploitation","Browser"],
        "url": "/securinets-sukunahikona/",
        "teaser": null
      }]
