#include "incs.h"
#include "listas/krlista.h"
#include "structs.h"

extern void *sys_call_table[];

/*
 * Configuration Options for the Module
 *
 */
extern t_gksm_opts gksm_opts;



/*
 *  IOCTL stuff
 *
 */



static int gksm_ioctl(struct inode *in, struct file *fi, unsigned int cmd, unsigned long args)
{
	t_gksm_up *gksm_bindpriv,*tmp_priv;
	t_ptr *lst;
        int err=-1;

	if (!current->euid) { /* only root can use this */
         switch (cmd) {
		case GKSM_ADDUIDPORT:
			if(!args) {
				err = -1;
				break;
			}
			gksm_bindpriv=(t_gksm_up*)kmalloc(sizeof(t_gksm_up),GFP_KERNEL);
			copy_from_user(gksm_bindpriv,(t_gksm_up*)args,sizeof(t_gksm_up));
			gksm_opts.privlst=krlista_insere(gksm_opts.privlst,(void *)gksm_bindpriv);
			if(gksm_opts.privlst) {
				printk("gksm: added cap bind for uid %i to port %i\n",gksm_bindpriv->uid,gksm_bindpriv->port);
				err = 0;
			} else {
				printk("gksm: failed to add cap bind for uid %i to port %i\n",gksm_bindpriv->uid,gksm_bindpriv->port);
				err = -1;
			}
			break;

		case GKSM_DELUIDPORT:
			if(!args) {
				err = -1;
				break;
			}
			gksm_bindpriv=(t_gksm_up*)kmalloc(sizeof(t_gksm_up),GFP_KERNEL);
			copy_from_user(gksm_bindpriv,(t_gksm_up*)args,sizeof(t_gksm_up));
			lst=gksm_opts.privlst;
			if(lst) {
				err = 1;
				tmp_priv=(t_gksm_up*)lst->st;
				if(gksm_bindpriv->uid==tmp_priv->uid) {
					gksm_opts.privlst=krlista_apaga(gksm_opts.privlst,(void*)tmp_priv);
					printk("gksm: removed cap bind for uid %i to port %i\n",gksm_bindpriv->uid,gksm_bindpriv->port);
					err = 0;
					break;
				}
				while(lst->next) {
					lst=lst->next;
					tmp_priv=(t_gksm_up*)lst->st;
					if(gksm_bindpriv->uid==tmp_priv->uid) {
						gksm_opts.privlst=krlista_apaga(gksm_opts.privlst,(void*)lst);
						printk("gksm: removed cap bind for uid %i to port %i\n",gksm_bindpriv->uid,gksm_bindpriv->port);
						err = 0;
						break;
					}
				}
					
			}
			break;
			
	}
       } 
	return err;
}

