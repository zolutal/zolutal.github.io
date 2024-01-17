---
layout: single
title: "Understanding x86_64 Paging"
date: 2023-12-27
classes: wide
tags:
  - x86_64
  - Linux
  - Architecture
---

I've spent quite a lot of time messing with x86_64 page tables, understanding address translation is not easy and when I started learning about it I felt like a lot of the material out there on how it works was hard for me to wrap my head around. So in this blog post I am going to attempt to provide a kind of "what I wish I had when learning about paging".

Quick note, I'll only be discussing paging in the context of PML4 (Page Map Level 4) since it's currently the dominant x86_64 paging scheme and probably will be for a while still.

## environment

Its not necessary, but I recommend that you have a Linux kernel debugging setup with QEMU + gdb prepared to follow along with. If you've never done this, maybe give this repo a shot: [easylkb](https://github.com/deepseagirl/easylkb) (I've never used it, but I've heard good things) or if you want to avoid having to setup the environment yourself, the practice mode on any of the Kernel Security challenges on [pwn.college](https://pwn.college/) would also work (`vm connect` and `vm debug` are the commands to know).

I suggest this because I think running the same commands I am on your own and being able to perform a page walk based on what you can see in gdb is a good test of understanding.

## wtf is a page

On x86_64 a page is a 0x1000 byte slice of memory which is 0x1000 byte aligned.

This is the reason why if you ever look at /proc/\<pid\>/maps you see that all the address ranges will start and end with an address ending with 0x000 because the minimum size of a memory mapping on x86_64 is page size (0x1000 bytes) and pages are required to be 'page aligned' (the last 12 bits must be zero).

A 'Virtual Page' will be resolved to a single 'Physical Page' (aka 'Page Frame') by your MMU though many Virtual Pages may refer to the same Physical Page.

## what is in a virtual address

PML4, as one might guess, has four level of paging structures, these paging structures are called 'Page Tables'. A page table is a page-sized memory region which contains 512 8-byte page table entries. Each entry of a page table will refer to either the next level page table or to the final physical address a virtual address resolves to.

The entry from a page table that is used for address translation is based on the virtual address of the memory access. With 512 entries per level, that means 9-bits of the virtual address are used at every level to index into the corresponding page table.

Say we have an address like this:

`0x7ffe1c9c9000`

The last 12 bits of this address represent the offset within the physical page:

`0x7ffe1c9c9000 & 0xfff = 0x0`

This means that once we determine the physical address of the page this virtual address resolves to, we will add zero to the result to get the final physical address.

After the last 12 bits, which is again just the offset within the final page, a virtual address is comprised of indicies into the page tables. As mentioned each level of paging uses 9 bits of the virtual address, so the lowest level of the paging structures, a Page Table, is indexed by the next 9 bits of the address (by bit masking with `& 0x1ff` on the shifted value). For the following levels we just need to shift right by another nine bits each time and again mask off the lower nine bits as our index. Doing this for the address above gives us these indicies:

```
Level 1, Page Table (PT):
Index = (0x7ffe1c9c9000 >> 12) & 0x1ff = 0x1c9

Level 2, Page Middle Directory (PMD):
Index = (0x7ffe1c9c9000 >> 21) & 0x1ff = 0x0e4

Level 3, Page Upper Directory (PUD):
Index = (0x7ffe1c9c9000 >> 30) & 0x1ff = 0x1f8

Level 4, Page Global Directory (PGD):
Index = (0x7ffe1c9c9000 >> 39) & 0x1ff = 0x0ff
```

## all your base

Now that we know how to index into page tables and vaguely what they contain, where actually are they???

Well each thread of your CPU has a page table base register called `cr3`.

`cr3` holds the physical address of the highest level of the paging structure, aka the Page Global Directory (PGD).

From gdb, when debugging the kernel, you can read the contents of `cr3` like this:

```
gef➤  p/x $cr3
$1 = 0x10d664000
```

The `cr3` register can hold some additional information besides just the PGD address depending on what processor features are in use, so a more general way of getting the physical address of the PGD from the `cr3` register is to mask off the lower 12 bits of its contents like so:

```
gef➤  p/x $cr3 & ~0xfff
$2 = 0x10d664000
```

## page table entries

Lets look at what is at that physical address we got from `cr3` in gdb. The `monitor xp/...` command that is exposed to gdb by the QEMU Monitor lets us print out the physical memory of the vm and doing `monitor xp/512gx ...` will print the entire contents, all 512 entries, of the PGD referred to by `cr3`:

```
gef➤  monitor xp/512gx 0x10d664000
...
000000010d664f50: 0x0000000123fca067 0x0000000123fc9067
000000010d664f60: 0x0000000123fc8067 0x0000000123fc7067
000000010d664f70: 0x0000000123fc6067 0x0000000123fc5067
000000010d664f80: 0x0000000123fc4067 0x0000000123fc3067
000000010d664f90: 0x0000000123fc2067 0x000000000b550067
000000010d664fa0: 0x000000000b550067 0x000000000b550067
000000010d664fb0: 0x000000000b550067 0x0000000123fc1067
000000010d664fc0: 0x0000000000000000 0x0000000000000000
000000010d664fd0: 0x0000000000000000 0x0000000000000000
000000010d664fe0: 0x0000000123eab067 0x0000000000000000
000000010d664ff0: 0x000000000b54c067 0x0000000008c33067
```

This produces a lot of output and most of it is zero, so I'm only including the tail of the output here.

This output probably doesn't mean much to you yet, but we can observe some patterns in the data, lots of the 8-byte entries end in `0x67`, for example.

## decoding a PGD entry

From the PGD output above, lets take the PGD entry at `0x000000010d664f50` with value `0x0000000123fca067` as an example to see how to decode an entry.

and lets do this with the binary representation of that entry's value:

```
gef➤  p/t 0x0000000123fca067
$6 = 100100011111111001010000001100111
```

Here is a little diagram to show what each bit in the entry represents:

```
~ PGD Entry ~                                                   Present ──────┐
                                                            Read/Write ──────┐|
                                                      User/Supervisor ──────┐||
                                                  Page Write Through ──────┐|||
                                               Page Cache Disabled ──────┐ ||||
                                                         Accessed ──────┐| ||||
                                                         Ignored ──────┐|| ||||
                                                       Reserved ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||               PUD Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
0000 0000 0000 0000 0000 0000 0000 0001 0010 0011 1111 1100 1010 0000 0110 0111
       56        48        40        32        24        16         8         0
```

and here's a key for what each of those labels mean:

- NX (Not Executable) -- if this bit is set, no memory mapping that is a descendant of this PGD entry will be executable.
- Reserved -- these values must be zero.
- PUD Physical Address -- the physical address of the PUD associated with this PGD entry.
- Accessed --  If any pages referred to by this entry or its descendants, this bit will be set by the MMU, and can be cleared by the OS.
- Page Cache Disabled (PCD) -- pages descendant of this PGD entry should not enter the CPU's cache hierarchy, sometimes also called the 'Uncacheable' (UC) bit.
- Page Write Through (WT) -- writes to pages descendant of this PGD entry should immediately write to RAM rather than buffering writes to CPU cache before eventually updating RAM.
- User/Supervisor -- if this bit is unset, pages descendant of this PGD cannot be accessed unless in supervisor mode.
- Read/Write -- if this bit is unset, pages descendant of this PGD cannot be written to.
- Present -- if this bit is unset then the processor will not use this entry for address translation and none of the other bits will apply.

The bits that we really care about here are the the Present bit, the ones representing the physical address of the next level of the paging structures, the PUD Physical Address bits, and the permission bits: NX, User/Supervisor, and Read/Write.

- The Present bit is super important because without it set the rest of the entry is ignored.
- The PUD Physical Address lets us continue page walking by telling us where the physical address of the next level of the paging structures is at.
- The Permission bits all apply to pages which are descendants of the PGD entry and determine how those pages are able to be accesssed.

The remaining bits are not as important for our purposes:
- The Accessed bit is set if the entry was used in translating a memory access, its not important for page walking.
- Page Cache Disabled and Page Write Through are not used for normal memory mappings and do not affect page translation or permissions so lets ignore them.

So decoding this entry, we learn:

The PUD is Present:
```
gef➤  p/x 0x0000000123fca067 & 0b0001
$18 = 0x1
```
The mappings in the PUD and below may be able to be Writable:
```
gef➤  p/x 0x0000000123fca067 & 0b0010
$19 = 0x2
```
The mappings in the PUD and below may be able to be User accessible:
```
gef➤  p/x 0x0000000123fca067 & 0b0100
$20 = 0x4
```
The PUD's physical address ( bits (51:12] ) is `0x123fca000`:
```
gef➤  p/x 0x0000000123fca067 & ~((1ull<<12)-1) & ((1ull<<51)-1)
$21 = 0x123fca000
```
The mappings in the PUD and below may be able to be Executable:
```
gef➤  p/x 0x0000000123fca067 & (1ull<<63)
$22 = 0x0
```

## decoding entries for all levels

Now that we've seen how to decode a PGD entry, decoding the rest of the levels aren't so much different, at least in the common case.

For all of these diagrams 'X' means the bit can be either zero or one, otherwise, if a bit is set to a specific value then that value is either required by the architecture or by the specific encoding shown by the diagram.

### PGD

```
~ PGD Entry ~                                                   Present ──────┐
                                                            Read/Write ──────┐|
                                                      User/Supervisor ──────┐||
                                                  Page Write Through ──────┐|||
                                               Page Cache Disabled ──────┐ ||||
                                                         Accessed ──────┐| ||||
                                                         Ignored ──────┐|| ||||
                                                       Reserved ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||               PUD Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX 0XXX XXXX
       56        48        40        32        24        16         8         0
```

This one we've already seen, I described it in detail in the previous section, but here it is without that specific PGD entry filled in.

### PUD

```
~ PUD Entry, Page Size unset ~                                  Present ──────┐
                                                            Read/Write ──────┐|
                                                      User/Supervisor ──────┐||
                                                  Page Write Through ──────┐|||
                                               Page Cache Disabled ──────┐ ||||
                                                         Accessed ──────┐| ||||
                                                         Ignored ──────┐|| ||||
                                                      Page Size ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||               PMD Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX 0XXX XXXX
       56        48        40        32        24        16         8         0
```

As you can see the diagram above for the PUD is very similar to the one for the PGD, the only difference is the introduction of the 'Page Size' bit. The Page Size bit being set changes how we need to interpret a PUD entry quite a lot. For this diagram we are assuming it is unset, which is the most common case.


### PMD

```
~ PMD Entry, Page Size unset ~                                  Present ──────┐
                                                            Read/Write ──────┐|
                                                      User/Supervisor ──────┐||
                                                  Page Write Through ──────┐|||
                                               Page Cache Disabled ──────┐ ||||
                                                         Accessed ──────┐| ||||
                                                         Ignored ──────┐|| ||||
                                                      Page Size ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||                PT Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX 0XXX XXXX
       56        48        40        32        24        16         8         0
```

Again, the PMD diagram is very similar to the previous diagram, and like with the PUD entry, we are ignoring the Page Size bit for now.

### PT

```
~ PT Entry ~                                                    Present ──────┐
                                                            Read/Write ──────┐|
                                                      User/Supervisor ──────┐||
                                                  Page Write Through ──────┐|||
                                               Page Cache Disabled ──────┐ ||||
                                                         Accessed ──────┐| ||||
┌─── NX                                                    Dirty ──────┐|| ||||
|┌───┬─ Memory Protection Key              Page Attribute Table ──────┐||| ||||
||   |┌──────┬─── Ignored                               Global ─────┐ |||| ||||
||   ||      | ┌─── Reserved                          Ignored ───┬─┐| |||| ||||
||   ||      | |┌──────────────────────────────────────────────┐ | || |||| ||||
||   ||      | ||            4KB Page Physical Address         | | || |||| ||||
||   ||      | ||                                              | | || |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
       56        48        40        32        24        16         8         0
```

At the Page Table entry things get more interesting, there are some new fields/attributes that weren't there in the previous levels.

Those new fields/attributes are:

- Memory Protection Key (MPK or PK): This is an x86_64 extension that allows assigning a 4-bit keys to pages which can be used to configure memory permissions for all pages with that key.
- Global: This has to do with how the TLB (Translation Lookaside Buffer, the MMU's cache for virtual to physical address translations) caches the translation for th page, this bit being set means the page will not be flushed from the TLB on context switch, this is commonly enabled on Kernel pages to reduce TLB misses.
- Page Attribute Table (PAT): If set, the MMU should consult the Page Attribute Table MSR when determining whether the 'Memory Type' of the page, e.g. whether this page is 'Uncacheable', 'Write Through', or one of a few other memory types.
- Dirty: This bit is similar to the accessed bit, it gets set by the MMU if this page was written to and must be reset by the OS.

None of these actually affect the address translation itself, but the configuration of the Memory Protection Key can mean that the expected memory access permissions for the page referred to by this entry may be stricter than what is encoded by the entry itself.

Unlike the previous levels, since this is the last level, the entry holds the final physical address of the page associated with the virtual address we are translating. Once you apply a bit-mask to get the physical address bytes and add the last 12 bits of the original virtual address (the offset within the page), you have your physical address!

Hopefully, this doesn't seem so bad, the general case of page walking is just a few steps:
- Convert the virtual address to indicies and a page offset by shifting the address and applying bitmasks
- Read `cr3` to get the physical address of the PGD
- For each level until the last:
    - Use the indicies calculated from the virtual address to know what entry from the page table to use
    - Apply a bitmask to the entry to get the physical address of the next level
- On the final level, again find the entry corresponding with the index from the virtual address
- Apply a bitmask to get the physical address of the page associated with the virtual address
- Add offset within the page from the virtual address to the page's physical address
- Done!


## hugeify

As mentioned, the previous diagrams for the PUD and PMD are for the common case, when the Page Size bit is not set.

So, what about when it is set?

When it is set that is effectively telling the MMU, pack it up, we're done here, don't keep page walking, the current entry holds the physical address of the page we are looking for.

But there is a bit more to it than that, the physical address of the page in entries where the Page Size bit is set isn't for a normal 4KB (0x1000 byte) page, it is a 'Huge Page' which comes in two variants: 1GB Huge Pages and 2MB Huge Pages.

When a PUD entry has the Page Size bit set then it refers to a 1GB Huge Page, and when a PMD has the Page Size bit set it refers to a 2MB Huge Page.

But where do the 1GB and 2MB numbers come from?

Each page table level holds up to 512 entries, that means a PT can refer to at most 512 pages and `512 * 4KB = 2MB`. So a Huge Page at the PMD level effectively means that the entry refers to a page that is the same size as a full PT.

Extending this to the PUD level, we just multiply by 512 again to get the size of a full PMD that has full PTs: `512 * 512 * 4KB = 1GB`.

### Huge Page PUD

```
~ PUD Entry, Page Size set ~                                     Present ─────┐
                                                             Read/Write ─────┐|
                                                       User/Supervisor ─────┐||
                                                   Page Write Through ─────┐|||
                                                Page Cache Disabled ─────┐ ||||
                                                          Accessed ─────┐| ||||
                                                            Dirty ─────┐|| ||||
┌─── NX                                                Page Size ─────┐||| ||||
|┌───┬─── Memory Protection Key                         Global ─────┐ |||| ||||
||   |┌──────┬─── Ignored                             Ignored ───┬─┐| |||| ||||
||   ||      | ┌─── Reserved           Page Attribute Table ───┐ | || |||| ||||
||   ||      | |┌────────────────────────┐┌───────────────────┐| | || |||| ||||
||   ||      | || 1GB Page Physical Addr ||      Reserved     || | || |||| ||||
||   ||      | ||                        ||                   || | || |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XX00 0000 0000 0000 000X XXXX 1XXX XXXX
       56        48        40        32        24        16         8         0
```

When the page size bit is set notice that the PUD entry looks more like a PT entry than a normal PUD entry, which makes sense because it is also referring to a page rather than a page table.

There are some distinctions from a PT entry though:
1. The Page Size bit is where the Page Attribute Table (PAT) bit is at on a PT, so the PAT bit is relocated to bit 12.
2. The physical address of a 1GB Huge Page is required to have 1GB alignment in physical memory, this is why the new reserved bits exist and why bit 12 is able to be repurposed as the PAT bit.

Overall, not too much new here, the only other differences when dealing with huge pages really is that a different bitmask needs to be applied to the address to get the bits for the physical address of the page, also the 1GB alignment means when calculating the physical address of a virtual address within the page we need to use a mask based on 1GB alignment instead of 4KB alignment.

### Huge Page PMD

```
~ PMD Entry, Page Size set ~                                     Present ─────┐
                                                             Read/Write ─────┐|
                                                       User/Supervisor ─────┐||
                                                   Page Write Through ─────┐|||
                                                Page Cache Disabled ─────┐ ||||
                                                          Accessed ─────┐| ||||
                                                            Dirty ─────┐|| ||||
┌─── NX                                                Page Size ─────┐||| ||||
|┌───┬─── Memory Protection Key                         Global ─────┐ |||| ||||
||   |┌──────┬─── Ignored                             Ignored ───┬─┐| |||| ||||
||   ||      | ┌─── Reserved         Page Attribute Table ─────┐ | || |||| ||||
||   ||      | |┌───────────────────────────────────┐┌────────┐| | || |||| ||||
||   ||      | ||     2MB Page Physical Address     ||Reserved|| | || |||| ||||
||   ||      | ||                                   ||        || | || |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXX0 0000 000X XXXX 1XXX XXXX
       56        48        40        32        24        16         8         0
```

This is very similar to the PUD entry with the Page Size bit set, the only thing that has changed is that since the alignment is smaller for the 2MB pages at this level, there are less reserved bits set.

The 2MB alignment means the offset within the huge page should be calculated using a mask based on 2MB alignment.


## going for a walk

So the last section was a lot of diagrams, in this section lets look at how to actually do a page walk manually in gdb.

### preparation

With a booted up vm and gdb attached I first will pick an address to do a page walk on, as an example I'll use the current stack pointer while running in the kernel:

```
gef➤  p/x $rsp
$42 = 0xffffffff88c07da8
```

Now we have the address we are going to walk, lets also get the physical address of the PGD from `cr3`:

```
gef➤  p/x $cr3 & ~0xfff
$43 = 0x10d664000
```

I'll use this little python function to extract the page table offsets from the virtual address:

```python
def get_virt_indicies(addr):
    pageshift = 12
    addr = addr >> pageshift
    pt, pmd, pud, pgd = (((addr >> (i*9)) & 0x1ff) for i in range(4))
    return pgd, pud, pmd, pt
```

which outputs this:
```python
In [2]: get_virt_indicies(0xffffffff88c07da8)
Out[2]: (511, 510, 70, 7)
```

### PGD

The index we got for the PGD based on the virtual address was 511, multiplying 511 by 8 will let us get the byte offset into the PGD that the PGD entry for our virtual address starts at:

```
gef➤  p/x 511*8
$44 = 0xff8
```

adding that offset to the PGD's physical address gets us the physical address of the PGD entry:

```
gef➤  p/x 0x10d664000+0xff8
$45 = 0x10d664ff8
```

and reading the physical memory at that address gets us the PGD entry itself:
```
gef➤  monitor xp/gx 0x10d664ff8
000000010d664ff8: 0x0000000008c33067
```

Looks like the entry has the last three bits (present, user, and writeable) set, and the top bit (NX) is unset, meaning there aren't any restrictions so far on the permissions of the pages associated with this virtual address.

Masking the bits [12, 51) gives us the physical address of the PUD:

```
gef➤  p/x 0x0000000008c33067 & ~((1<<12)-1) & ((1ull<<51) - 1)
$46 = 0x8c33000
```

### PUD

The index we got for the PUD based on the virtual address was 510, multiplying 510 by 8 will let us get the byte offset into the PUD that the PUD entry for our virtual address starts at:

```
gef➤  p/x 510*8
$47 = 0xff0
```

adding that offset to the PUD's physical address gets us the physical address of the PUD entry:

```
gef➤  p/x 0x8c33000+0xff0
$48 = 0x8c33ff0
```

and reading the physical memory at that address gets us the PUD entry itself:
```
gef➤  monitor xp/gx 0x8c33ff0
0000000008c33ff0: 0x0000000008c34063
```

At this level we need to start paying attention to the Size Bit (bit 7), because if it is a 1GB page we would stop our page walk here.

```
gef➤  p/x 0x0000000008c34063 & (1<<7)
$49 = 0x0
```

Seems it is unset on this entry so we will continue page walking.

Notice also that the PUD entry ends in 0x3 and not 0x7 like the previous level, the bottom two bits (present, writeable) are still set but the third bit, the user bit is now unset. That means that usermode accesses to pages belonging to this PUD entry will result in a page fault due to the failed permission check on the access.

The NX bit is still unset, so pages belonging to this PUD can still be executable.

Masking the bits [12, 51) gives us the physical address of the PMD:

```
gef➤  p/x 0x0000000008c34063 & ~((1ull<<12)-1) & ((1ull<<51)-1)
$50 = 0x8c34000
```

### PMD

The index we got for the PMD based on the virtual address was 70, multiplying 70 by 8 will let us get the byte offset into the PMD that the PMD entry for our virtual address starts at:

```
gef➤  p/x 70*8
$51 = 0x230
```

adding that offset to the PMD's physical address gets us the physical address of the PMD entry:

```
gef➤  p/x 0x8c34000+0x230
$52 = 0x8c34230
```

and reading the physical memory at that address gets us the PMD entry itself:
```
gef➤  monitor xp/gx 0x8c34230
0000000008c34230: 0x8000000008c001e3
```

Again, at this level we need paying attention to the Size Bit, because if it is a 2MB page we will stop our page walk here.

```
gef➤  p/x 0x8000000008c001e3 & (1<<7)
$53 = 0x80
```

Looks like our virtual address refers to a 2MB Huge Page! so the physical address in this PMD entry is the physical address of that Huge Page.

Also, looking at the permission bits, looks like the page is still present and writeable and the user bit is still unset, so this page is only accessible from supervisor mode (ring-0).

Unlike the previous levels, the top bit, the NX bit, is set:

```
gef➤  p/x 0x8000000008c001e3 & (1ull<<63)
$54 = 0x8000000000000000
```

So this Huge Page is not executable memory.

Applying a bitmask on bits [21:51) gets us the physical address of the huge page:

```
gef➤  p/x 0x8000000008c001e3 & ~((1ull<<21)-1) & ((1ull<<51)-1)
$56 = 0x8c00000
```

Now we need to apply a mask to the virtual address based on 2MB page alignment to get the offset into the Huge Page.

2MB is equivalent to `1<<21` so applying a bitmask of `(1ull<<21)-1` will get us the offset:

```
gef➤  p/x 0xffffffff88c07da8 & ((1ull<<21)-1)
$57 = 0x7da8
```

Now adding this offset to the base address of the 2MB Huge Page will get us the physical address associated with the virtual address we started with:

```
gef➤  p/x 0x8c00000 + 0x7da8
$58 = 0x8c07da8
```

Looks like the Virtual Address: `0xffffffff88c07da8` has a Physical Address of: `0x8c07da8`!

### checking ourselves

There are a few ways to test that we page walked correctly, an easy check is to just dump the memory at the virtual and physical address and compare them, if they look the same we were probably right:

Physical:
```
gef➤  monitor xp/10gx 0x8c07da8
0000000008c07da8: 0xffffffff810effb6 0xffffffff88c07dc0
0000000008c07db8: 0xffffffff810f3685 0xffffffff88c07de0
0000000008c07dc8: 0xffffffff8737dce3 0xffffffff88c3ea80
0000000008c07dd8: 0xdffffc0000000000 0xffffffff88c07e98
0000000008c07de8: 0xffffffff8138ab1e 0x0000000000000000
```

Virtual:
```
gef➤  x/10gx 0xffffffff88c07da8
0xffffffff88c07da8:	0xffffffff810effb6	0xffffffff88c07dc0
0xffffffff88c07db8:	0xffffffff810f3685	0xffffffff88c07de0
0xffffffff88c07dc8:	0xffffffff8737dce3	0xffffffff88c3ea80
0xffffffff88c07dd8:	0xdffffc0000000000	0xffffffff88c07e98
0xffffffff88c07de8:	0xffffffff8138ab1e	0x0000000000000000
```

Looks good to me!

Another way to check is using the `monitor gva2gpa` (guest virtual address to guest physical address) command exposed to gdb by the QEMU Monitor:

```
gef➤  monitor gva2gpa 0xffffffff88c07da8
gpa: 0x8c07da8
```

Assuming QEMU is doing address translation correctly (probably a fair assumption), then looks like we have double confirmation that our page walk was successful!

## wrapping up

Hopefully by the end of this you have a pretty solid understanding of how paging works on x86_64 systems. I wanted to pack a lot of information into the post so it took some thought to figure out how to organize all of it and I'm still not sure if this was a great way to go about it.

Anyways, I think paging is pretty neat and I think its one of those things where once you get it you've got it, but getting to that point can take some time and some screwing around in gdb.

I'd also like to mention that the inspiration for the diagrams of the various page table entries I made for this post came from the documentation of the [blink](https://github.com/jart/blink/) project: [blink/machine.h](https://github.com/jart/blink/blob/46d82a0ced97c0df1fc645c5d81a88f0d142fbfd/blink/machine.h#L61).

Thanks for reading!
