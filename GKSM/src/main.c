/* $Id: main.c,v 1.4 2002/06/03 20:09:43 mori Exp $ */

#include "incs.h"
#include "listas/krlista.h"
#include "structs.h"


/*
 * Module initialization stuff
 * syscall replacement
 *
 */

extern void *sys_call_table[];

asmlinkage long (*old_socketcall)(int,unsigned long *);
asmlinkage long new_socketcall(int, unsigned long *);

/*
 * Create IOCTL for the device
 */
extern int gksm_ioctl(struct inode *in, struct file *fi, unsigned int cmd, unsigned long args);

static struct file_operations fops = {
ioctl: gksm_ioctl
}; 


/*
 * Configuration Options for the Module
 *
 */
static t_gksm_opts gksm_opts;


/*
 *   initialization
 */

#define O_TO_NEW(x) old_##x=sys_call_table[__NR_##x]; sys_call_table[__NR_##x]=new_##x;
#define N_TO_OLD(x) sys_call_table[__NR_##x]=old_##x;


int init_module(void) {
#ifdef _README_
	return -1;
#endif

        lock_kernel();
	O_TO_NEW(socketcall);

       /*
        * Crate device for the ioctl
        */
	SET_MODULE_OWNER(&fops);
	if(register_chrdev(241, "gksm", &fops)) 
	       return -EIO;	

        unlock_kernel();
	printk(KERN_INFO "GKSM initialized\n");
        return 0;
}


int cleanup_module(void) {

        lock_kernel();


	N_TO_OLD(socketcall);

        unregister_chrdev(241, "gksm");	


	krlista_destroi(gksm_opts.privlst);
        printk ("GKSM unloaded\n");
        unlock_kernel();
        return 0;
}

