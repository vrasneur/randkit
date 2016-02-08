#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Rasneur <vrasneur@free.fr>");
MODULE_DESCRIPTION("Randkit fops: access to struct file_operations * pointer from /dev/urandom");

static unsigned long urandom_fops_addr;
module_param(urandom_fops_addr, ulong, 0);

static struct file_operations *rk_param_get_fops(void)
{
    return (struct file_operations *)urandom_fops_addr;
}

static struct file_operations *rk_vfs_get_fops(int minor)
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

    list_del(&inode.i_devices);
  
    // remove the const correctness
    return (struct file_operations *)fp.f_op;
}

static struct file_operations *rk_kallsyms_get_fops(char const *name)
{
    return (struct file_operations *)kallsyms_lookup_name(name);
}

static void rk_check_fops(struct file_operations *fops, char const *way)
{
    if(fops == NULL) {
        printk(KERN_INFO "using '%s': cannot find the fops\n", way);
    }
    else if(fops->read != NULL)
    {
        printk(KERN_INFO "using '%s': found fops at %p, read is at %p\n", way, fops, fops->read);
    }
    else {
        printk(KERN_INFO "using '%s': found fops at %p, read not found", way, fops);
    }
}

static void rk_test_fops(void)
{
    struct file_operations *urandom_fops = NULL;
    printk(KERN_INFO "getting urandom fops\n");
    
    urandom_fops = rk_vfs_get_fops(9);
    rk_check_fops(urandom_fops, "vfs");

    urandom_fops = rk_kallsyms_get_fops("urandom_fops");
    rk_check_fops(urandom_fops, "kallsyms");

    urandom_fops = rk_param_get_fops();
    rk_check_fops(urandom_fops, "param");

    printk(KERN_INFO "getting done\n");
}

static int __init rk_init(void)
{
    rk_test_fops();

    return 0;
}

static void __exit rk_cleanup(void)
{

}

module_init(rk_init);
module_exit(rk_cleanup);
