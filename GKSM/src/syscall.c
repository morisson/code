/* $Id: syscall.c,v 1.3 2002/06/03 20:09:43 mori Exp $ */
#include "incs.h"
#include "listas/krlista.h"
#include "structs.h"

/*
 *  Common variables and structures
 *
 */ 

extern t_gksm_opts gksm_opts;


/*
 *
 * Syscalls to replace
 *
 *
 */
extern void *sys_call_table[];

extern asmlinkage long (*old_socketcall)(int,unsigned long *);
asmlinkage long new_socketcall(int, unsigned long *);


inline int can_bind(unsigned short sport) {
    t_ptr *lst;
    t_gksm_up *bindpriv;
#ifdef _DEBUG_
    printk("can uid %i bind ? \n",current->euid);
#endif
    
    lst=gksm_opts.privlst;
    while(lst) {
	  bindpriv=lst->st;
          if(current->euid==bindpriv->uid) {
#ifdef _DEBUG_
		printk(" euid: %i binduid: %i \n",current->euid,bindpriv->uid);
#endif
               if(bindpriv->port==sport)
                 return 1; 
	  }
	  lst=lst->next; 
    }
    return 0; 
}


/*
 *  New socket syscall funcion (ripped from kernel source)
 */


/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
                                AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
                                AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
#undef AL


asmlinkage long new_socketcall(int call, unsigned long *args)
{
        unsigned long a[6];
        struct sockaddr_in *bind_struct;
        unsigned short snum;
	kernel_cap_t o_cap;
	int res;
        
        if(call<1||call>SYS_RECVMSG)
                return -EINVAL;
        
       if (copy_from_user(a, args, nargs[call]))
                return -EFAULT;

       /*save current capabilites*/
       o_cap=current->cap_effective;
       if(current->euid) { /* if it's root, we don't care*/
        switch(call) {
                case SYS_BIND:
                   bind_struct=((struct sockaddr_in *)a[1]);
                   snum = ntohs(bind_struct->sin_port);
                   if((snum < 1024)&&(can_bind(snum))) {
                           cap_raise(current->cap_effective,CAP_NET_BIND_SERVICE);
                           printk("Capability CAP_NET_BIND_SERVICE to port %i raised for uid %i\n",snum,current->euid);
                   }
                   break;
         }
        }
        res = old_socketcall(call,args);
	/* Drop capability*/
	current->cap_effective=o_cap;
        return res;
}
