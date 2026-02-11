#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/efi.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>

/* forward declarations */
void *lookup_kallsyms_lookup_name(void);
static ssize_t proc_read(struct file* filep, char* __user buffer, size_t len, loff_t* offset);
static ssize_t proc_write(struct file* filep, const char* __user u_buffer, size_t len, loff_t* offset);
static int proc_open(struct inode *inode, struct file *filep);
static long proc_ioctl(struct file *, unsigned int, unsigned long);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
static struct proc_ops fops = {
    .proc_open = proc_open,
    .proc_read = proc_read,
    .proc_write = proc_write,
    .proc_ioctl = proc_ioctl,
};
#else
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = proc_open,
    .read = proc_read,
    .write = proc_write,
};
#endif


static int proc_open(struct inode *inode, struct file *filep)
{
    pr_info("[%s]: open\n", THIS_MODULE->name);
    return 0;
}

static ssize_t proc_read(struct file* filep, char* __user buffer, size_t len, loff_t* offset)
{
    return 0;
}

static ssize_t proc_write(struct file* filep, const char* __user u_buffer, size_t len, loff_t* offset)
{
    return 0;
}


struct arb_call_req {
    __user uint64_t *pc;
    __user uint64_t *a0;
    __user uint64_t *a1;
};

static ssize_t proc_ioctl(struct file* filep, unsigned int cmd, unsigned long arg)
{
    __user struct arb_call_req *user_req = arg;
    struct arb_call_req req;

    pr_info("[%s]: ioctl %lx %lx\n", THIS_MODULE->name, cmd, arg);
    get_user(req.pc, &user_req->pc);
    get_user(req.a0, &user_req->a0);
    get_user(req.a1, &user_req->a1);
    //pr_info("[%s]: ioctl %lx %lx\n", THIS_MODULE->name, req.pc, req.a0);

    //pr_info("[%s]: ioctl\n", THIS_MODULE->name);

    void (*target)(void *, void*) = (void (*)(void *, void *))req.pc;
    target(req.a0, req.a1);

    return 0;
}

static int __init proc_init(void)
{
    struct proc_dir_entry *new;
    new = proc_create("dbg-mod", 0777, NULL, &fops);
    pr_info("[%s]: init\n", THIS_MODULE->name);
    return 0;
}

static void __exit proc_exit(void)
{
    remove_proc_entry("dbg-mod", NULL);
    pr_info("[%s]: exit\n", THIS_MODULE->name);
}

/* entry/exit points of the module */
module_init(proc_init);
module_exit(proc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zolutal");
MODULE_DESCRIPTION("does things");
MODULE_VERSION("0.1");
