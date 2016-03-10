#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincent Rasneur <vrasneur@free.fr>");
MODULE_DESCRIPTION("Randkit fops: access to struct file_operations * pointer from /dev/urandom");

static unsigned long urandom_fops_addr;
module_param(urandom_fops_addr, ulong, 0);

static struct file_operations *rk_param_get_fops(void)
{
    return (struct file_operations *)urandom_fops_addr;
}

static struct file_operations *rk_inode_get_fops(struct inode *inode)
{
    struct file fp;
    struct address_space mapping;

    memset(&fp, 0, sizeof(fp));
    memset(&mapping, 0, sizeof(mapping));
    // memory_open (called by chrdev_open)
    // needs the f_mapping pointer on old 3.x kernels
    fp.f_mapping = &mapping;
  
    // inode.i_fop->open == chrdev_open
    inode->i_fop->open(inode, &fp);

    // remove the const correctness
    return (struct file_operations *)fp.f_op;
}

static struct file_operations *rk_chrdev_get_fops(int minor)
{
    struct inode inode;
    struct file_operations *fop = NULL;
  
    memset(&inode, 0, sizeof(inode));
    // chrdev_open needs a doubly linked list here
    INIT_LIST_HEAD(&inode.i_devices);
    // get a pointer to chrdev_open
    init_special_inode(&inode, S_IFCHR, MKDEV(1, minor));

    if(inode.i_fop != NULL && inode.i_fop->open != NULL) {
        // call chrdev_open, that will call memory_open
        fop = rk_inode_get_fops(&inode);
    }

    list_del(&inode.i_devices);
    
    return fop;
}

static struct file_operations *rk_filp_get_fops(char const *name)
{
    struct file *fp = filp_open(name, O_RDONLY, 0);
    struct file_operations *fop = NULL;

    if(!IS_ERR(fp)) {
        // remove the const correctness
        fop = (struct file_operations *)fp->f_op;
        
        filp_close(fp, NULL);
    }
    
    return fop;
}

static struct file_operations *rk_path_get_fops(char const *name)
{
    struct path path;
    struct file_operations *fop = NULL;
    struct inode *inode = NULL;
    
    int ret = kern_path(name, LOOKUP_FOLLOW, &path);
    if(ret == 0) {
        inode = d_backing_inode(path.dentry);

        if(inode->i_fop != NULL && inode->i_fop->open != NULL) {
            // call chrdev_open, that will call memory_open
            fop = rk_inode_get_fops(inode);
        }
    }

    return fop;
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
    struct file_operations *urandom_fops_ptr = NULL;
    printk(KERN_INFO "getting pointer to urandom fops\n");
    
    urandom_fops_ptr = rk_chrdev_get_fops(9);
    rk_check_fops(urandom_fops_ptr, "chrdev");

    urandom_fops_ptr = rk_kallsyms_get_fops("urandom_fops");
    rk_check_fops(urandom_fops_ptr, "kallsyms");

    urandom_fops_ptr = rk_path_get_fops("/dev/urandom");
    rk_check_fops(urandom_fops_ptr, "path");

    urandom_fops_ptr = rk_filp_get_fops("/dev/urandom");
    rk_check_fops(urandom_fops_ptr, "filp");
    
    urandom_fops_ptr = rk_param_get_fops();
    rk_check_fops(urandom_fops_ptr, "param");

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
