---
layout: single
title:  "The Joys of Linux Kernel ROP Gadget Scanning"
date: 2025-09-03
classes: wide
tags:
  - Exploitation
  - Linux
---

Linux Kernel ROP gadget scanning is one of those things that seems easy in theory -- just run `ROPgadget --binary vmlinux` on it!
In practice, however, anyone who has used that method has likely had to sift through a large amount of false positives and likely missed some gadgets due to false negatives.
This is a result of a few quirks of Linux kernel images, some of which make solving the false positive/negative problems a bit difficult.

I want to use this post to describe some of the complexity behind static ROP gadget scanning in modern Linux kernel images and discuss how I handle them in my fork of [ropr](https://github.com/Ben-Lichtman/ropr) called [kropr](https://github.com/zolutal/kropr).

# The Executable Section Problem

Lets start with probably the most well known problem leading to false positives, the fact that generic ROP gadget scanners do not account for some sections of the kernel being only executable at boot time.

Here are all the executable regions in a Ubuntu kernel image (output from readelf):

```
Section Headers:
  [Nr] Name                  Type             Address           Offset
       Size                  EntSize          Flags  Link  Info  Align
  [ 1] .text                 PROGBITS         ffffffff81000000  00001000
       0000000001600000      0000000000000000  AX       0     0     4096
  [21] .init.text            PROGBITS         ffffffff838ae000  02850000
       00000000000c8725      0000000000000000  AX       0     0     16
  [22] .altinstr_aux         PROGBITS         ffffffff83976725  02918725
       00000000000032b2      0000000000000000  AX       0     0     1
  [29] .altinstr_replacement PROGBITS         ffffffff83d4728a  02ce9286
       0000000000008dcd      0000000000000000  AX       0     0     1
  [31] .exit.text            PROGBITS         ffffffff83d50090  02cf2090
       00000000000046a5      0000000000000000  AX       0     0     16
```

This vmlinux contains five executable sections, all of which in a normal binary would be viable locations to find ROP gadgets. However, for the Linux kernel, this is not the case.

We can see this by booting the kernel and looking at the output from the [gdb-pt-dump](https://github.com/martinradev/gdb-pt-dump) utility in gdb, which dumps the page tables along with their permissions/attributes:

```
gef> pt
             Address :     Length   Permissions                 Region
...
  0xffffffff81000000 :  0x1600000 | W:0 X:1 S:1 UC:0 WB:1 G:1 | kernel
  0xffffffff82600000 :   0xda0000 | W:0 X:0 S:1 UC:0 WB:1 G:1 | kernel
  0xffffffff833a0000 :   0x9c5000 | W:1 X:0 S:1 UC:0 WB:1 G:1 | kernel
  0xffffffff83d65000 :     0x1000 | W:0 X:0 S:1 UC:0 WB:1 G:1 | kernel
  0xffffffff83d66000 :   0x69a000 | W:1 X:0 S:1 UC:0 WB:1 G:1 | kernel
...
```

The only executable region here matches with what we saw in the `readelf` output previously for the `.text` section. As such, the `.text` section is the only one we should care about when scanning for gadgets.

In kropr, I address this source of false positives by just filtering for the `.text` section when parsing the kernel image.

# The Thunk Problem

In response to speculative execution vulnerabilities, Linux had to do some strange things to control flow instructions to mitigate particular attacks.
One of these measures was to turn all returns and all calls/jumps into calls/jumps to thunks.

Here is an example of what this actually looks like:

```
gef> disas free_pipe_info
Dump of assembler code for function free_pipe_info:
   0xffffffff814fc470 <+0>:	nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff814fc475 <+5>:	push   rbp
   0xffffffff814fc476 <+6>:	mov    rbp,rsp
   0xffffffff814fc479 <+9>:	push   r12
   0xffffffff814fc47b <+11>:	push   rbx
...
   0xffffffff814fc4df <+111>:	mov    rax,QWORD PTR [rax+0x8]
   0xffffffff814fc4e3 <+115>:	call   0xffffffff8222fcc0 <__x86_indirect_thunk_rax>
...
   0xffffffff814fc52a <+186>:	pop    rbx
   0xffffffff814fc52b <+187>:	pop    r12
   0xffffffff814fc52d <+189>:	pop    rbp
   0xffffffff814fc52e <+190>:	xor    eax,eax
   0xffffffff814fc530 <+192>:	xor    edx,edx
   0xffffffff814fc532 <+194>:	xor    esi,esi
   0xffffffff814fc534 <+196>:	xor    edi,edi
   0xffffffff814fc536 <+198>:	jmp    0xffffffff82230460 <__x86_return_thunk>
```

In the above code, where you would expect to see an indirect call we instead see a call to `__x86_indirect_thunk_rax`, and where you would expect to see a `ret` instruction at the end of the function we instead see a jump to `__x86_return_thunk`.

These thunks are actually due to mitigations against two different microarchitectural vulnerabilities. One of which is Spectre V2, which can be mitigated via [retpolines](https://security.googleblog.com/2018/01/more-details-about-mitigations-for-cpu_4.html). This is the mitigation that adds `__x86_indirect_thunk_<register>` calls to the code in place of the expected `call <register>` instructions. The other vulnerability is [Retbleed](https://comsec.ethz.ch/research/microarch/retbleed/), which can be mitgated via a jmp2ret (more details can be found in the retbleed paper), which is the mitigation that adds `__x86_return_thunk` jumps in place of return instructions.

So, how do these thunks affect ROP gadget scanning? Well, they actually cause some pretty major problems...

## False Negatives From Thunks

Here is an example of some output from kropr, ropr, and ROPgadget:

```
┌──(jmill@ubun)-[~]
└─$ kropr --patch-rets=false --patch-retpolines=false ./ubuntu-vmlinux | grep 0xffffffff8191f11c
0xffffffff8191f11c: pop rdi; jmp 0xffffffff82230460 <__x86_return_thunk>;

==> Found 175774 gadgets in 1.579 seconds

┌──(jmill@ubun)-[~]
└─$ ropr ./ubuntu-vmlinux | grep 0xffffffff8191f11c

==> Found 456762 gadgets in 2.583 seconds

┌──(jmill@ubun)-[~]
└─$ ROPgadget --binary ./ubuntu-vmlinux | grep 0xffffffff8191f11c
0xffffffff8191f11c : pop rdi ; jmp 0xffffffff82230460
```

( ignore the kropr flags for now, we'll get to those later )

You can see there is a `pop rdi; ret;` gadget that ropr is *entirely unable to find* because they do not account for thunked returns.
On the other hand, ROPgadget is actually able to find it, but its output makes it unclear that this is actually a ROP gadget rather than a JOP (Jump Oriented Programming) gadget.

So, this is an instance of a false negative in the case of ropr, and a true positive that is difficult to visually parse in the case of ROPgadget which may lead to it being overlooked.

I address this in kropr, as can be seen in the above output, by adding symbol names for thunked calls/jumps/returns.

## False Positives From Thunks

So, as we saw, thunks can introduce false negatives, but as it turns out they can also introduce false positives!

Here is an example of two gadgets found by kropr:

```
0xffffffff810c41ff: jmp 0xffffffff82230460 <__x86_return_thunk>;
0xffffffff810c4200: pop rsp; ret 0x116;
```

Notice that these gadgets are 1 byte apart in memory, the second gadget actually starts with an unaligned instruction in the second byte of the jump instruction in the first gadget.
This is kind of interesting, because normally `ret` is a single byte instruction (0xc3) meaning there cannot be an unaligned instruction inside of it, but as a result of these mitigations we now have these extra unaligned gadgets.

So... that second gadget is real, right?

Well, maybe?

The thing is, `__x86_return_thunk` is, as was stated, a mitigation against the Retbleed vulnerability. Retbleed only impacted AMD's Zen 1-2 CPUs, and this mitigation comes with a performance hit. To dodge that perf hit on unaffected CPUs, Kernel developers made it so these thunks are conditionally applied at runtime. The kernel will actually patch itself during startup depending on what CPU you are running it on.

If you are running Zen 1-2 CPU affected by Retbleed, then it *is a real gadget*, it will be present at runtime.
On other CPUs, which are not affected by Retbleed, these gadgets are false positives because the thunk will be patched to something else.

As an example, lets check on my Zen 3 CPU running this kernel under Qemu with KVM enabled and the `--cpu host` argument being passed:

```
gef> x/i 0xffffffff810c41ff
   0xffffffff810c41ff:	jmp    0xffffffff8250410b <srso_alias_return_thunk>
gef> x/i 0xffffffff810c41ff+1
   0xffffffff810c4200:	(bad)
```

wat.

So, Zen 3 is actually vulnerable to an *entirely different return instruction related speculative execution vulnerability* called [Speculative Return Stack Overflow](https://comsec.ethz.ch/research/microarch/inception/) (SRSO, aka Inception). This vulnerability has its own thunk, `srso_alias_return_thunk` that gets patched over the `jmp __x86_return_thunk` instructions at boot if your CPU is vulnerable to SRSO.

So, I guess its at this point that I wrap up the blog and admit that static ROP gadget discovery for the Linux kernel is impractical to do without some false negatives/positives or full knowledge of all of the CPU features and mitigations applicable to the target system.

Or it would be, but actually I'm not done yapping quite yet !!!

## Thunk Patching

Just because it is impractical to account for all possible CPUs someone might be using, doesn't mean it isn't worth trying to make a *reliable* ROP gadget scanner!
What I want is a happy medium default configuration between having low false negatives but eliminating as many false positives as possible.

In kropr, to deal with the thunks problem I actually patch out all of the thunk calls/jump/returns by default, eliminating false positives from unaligned instructions inside thunks while having a nice side effect of making gadgets that contain thunks look more like you would expect them to.

If you remember from earlier in the post I said to ignore the arguments in this command:

```
┌──(jmill@ubun)-[~]
└─$ kropr --patch-rets=false --patch-retpolines=false ./ubuntu-vmlinux | grep 0xffffffff8191f11c
0xffffffff8191f11c: pop rdi; jmp 0xffffffff82230460 <__x86_return_thunk>;
```

Well, here is the output without those arguments (though I needed to add `--nouniq` to prevent the gadget from being deduplicated with the other `pop rdi; ret` gadgets):

```
┌──(jmill@ubun)-[~]
└─$ kropr --nouniq ./ubuntu-vmlinux | grep 0xffffffff8191f11c
0xffffffff8191f11c: pop rdi; ret;
```

Kinda nice, eh? its not a thunk anymore, its just a normal return!

And the same is true of retpoline thunks:

```
┌──(jmill@ubun)-[~]
└─$ kropr --patch-retpolines=false ./ubuntu-vmlinux | grep 0xffffffff810efe0b
0xffffffff810efe0b: jmp 0xffffffff8222fda0 <__x86_indirect_thunk_rdi>;

┌──(jmill@ubun)-[~]
└─$ kropr --nouniq ./ubuntu-vmlinux | grep 0xffffffff810efe0b
0xffffffff810efe0b: jmp rdi;
```

Its just a normal jump now!

Additionally, the case earlier with the unaligned instruction inside the ret thunk has also been addressed, because the return is back to being a single-byte instruction:

```
Before:
0xffffffff810c41ff: jmp 0xffffffff82230460 <__x86_return_thunk>;
0xffffffff810c4200: pop rsp; ret 0x116;

After:
0xffffffff810c41ff: ret;
```

So, what is this witchcraft? am I doing some cursed post-processing string replacement?

Nope, but honestly that might have been easier!

Instead, what I do in kropr is partially re-implent the kernel's self-patching routine that happens when a CPU is not vulnerable to any vulnerabilities that necessitate thunked calls, jumps, or returns. The code that does this in Linux can be found [here](https://github.com/torvalds/linux/blob/v6.16/arch/x86/kernel/alternative.c#L1049) for returns, and [here](https://github.com/torvalds/linux/blob/v6.16/arch/x86/kernel/alternative.c#L945) for retpoline jumps/calls.

In short, for returns it iterates over the entries in the `.return_sites` section of the kernel image, which contains offsets to all of the jump instructions to thunked returns. It then replaces the thunks with a `ret` instruction followed by four `int3` instructions to replace the entire jump instruction.

For retpolines it iterates of the entries in the `.retpoline_sites` section of the kernel image, which contains offsets to all of the calls/jumps to retpoline thunks. For each instruction it will decode the instruction to determine which register the thunk corresponds to and whether it is a call or jump instruction. It then patches over the existing thunk instruction with the typical version (e.g. `call __x86_indirect_thunk_rdi` becomes `call rdi`) and then fills the remaining space after the previous instruction with nop instructions.

There is some additional complexity in each of these routines that I'm glossing over which deals with various kernel configurations and other microarchitectural mitigations, but they aren't all that important for the purposes of finding reliable gadgets.

# The Alternatives Problem

As though the Thunk Problem wasn't enough of a doozy, dealing with 'alternatives' is even more painful, I don't even try to account for them at the moment in kropr!

So, what is an 'alternative'?

The Linux kernel supports many different x86\_64 processors that support many different hardware features, some of these features determine whether some instructions are valid on the processor or not. Newer generations of processors may introduce new instructions which are related to security features or even just provide a faster alternative to an existing instruction.

Alternatives, in the context of the Linux kernel, account for this case where an instruction at some address should be some instruction by default but should be a different instruction if the CPU features allow it.

For example, CPUs started to support SMAP (Supervisor Mode Access Prevention) in 2012, which introduced two instructions -- `stac` and `clac`. The `stac` instruction sets a bit in the `eflags` register which temporarily disables the enforcement of SMAP, and the `clac` instruction clears that bit reenabling the enforcement of SMAP.
If you've ever wondered how the function `copy_from_user` in the kernel works when SMAP is enabled, this is how. They do `stac` -> `memory read` -> `clac`, temporarily bypassing SMAP enforcement for the access of userspace memory.

On a CPU that doesn't support the SMAP feature, these instructions would raise an Invalid Opcode exception. This means that the kernel needs to only use the `stac` and `clac` instructions in `copy_from_user` if the SMAP feature is actually supported. Alternatives are what make this possible.

There is section of the kernel image for alternatives called `.altinstructions` which specifies
- A location for an instruction that should be conditionally replaced
- An offset into another section called `.altinstr_replacement` which contains the alternate instruction's code
- A 'cpuid' value representing a CPU feature related to this alternative
- A 'flags' value used to specify additonal information about when the alternative should be applied
- The length of the original instruction
- The length of the replacement instruction

The actual struct for these entries in the `.altinstructions` section that is used by the kernel can be found [here](https://github.com/torvalds/linux/blob/v6.16/arch/x86/include/asm/alternative.h#L68-L82).

Since these instructions can be replaced during boot, they serve as a source of both false positives and false negatives. An instruction in a gadget might be replaced at runtime, creating a false positive, and a useful instruction could only be present at runtime creating a false negative.

When doing static ROP gadget scanning there is no way to know what CPU the user is targeting without their input. The data from the host's CPU could be enumerated via `cpuid` but that will be different than the set of CPU features supported in a Qemu VM, even if using KVM and passing the `--cpu host`! If the VM specifies `--cpu kvm64` or `--cpu qemu64` the set of features will be even less similar to that of the host.

I think there are a few options to address this problem:
- Allow the user to provide a CPUID dump or `/proc/cpuinfo` content from the target kernel
- Allow the user to specify a CPU model and have a database of what features common CPUs support
- Provide an option that filters out any gadgets that overlap with any of the instructions in `.altinstructions` to remove any false positives
- Provide a reasonable default configuration of alternatives to apply, e.g., I think we can assume that most CPUs support SMAP related instructions these days

While I do want to support some of these in kropr eventually, none of these options are currently implemented. I don't think alternatives have a major impact on the number of false positives/negatives, at least not anywhere near as bad as the other problems I discussed. All of these replacements are related to the CPU architecture, which means there aren't *that* many of them and the replacements *mostly* add instructions that are not typically used in ROP chains.

# The Conclusion Problem

Thanks for reading, that's all I've got :3

This whole rabbit hole of trying to improve Linux kernel ROP gadget discovery was really fun to go down, and led to the creation of what I think is a pretty useful tool!

At this point kropr has existed as a fork for a bit over a year and I've been using it or kernel pwn since its creation.
Despite never really advertising it outside of my lab its actually gained a decent amount of attention, which is always nice to see.
Anyways, if you do any Linux kernel pwn you should check it out and open an issue on the repo if you run into any problems while using it!

Github Link: [https://github.com/zolutal/kropr](https://github.com/zolutal/kropr)
