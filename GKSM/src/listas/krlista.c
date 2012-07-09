/*
 * generic kernel linked lists functions.
 * Original code by Marco Vaz <zav@genhex.org>
 * modified by Bruno Morisson <morisson@genhex.org>
 *
 */

#include "krlista.h"


t_ptr *krlista_insere(t_ptr *lst, void *buffer){
  t_ptr *no;

  no=(t_ptr*)kmalloc(sizeof(t_ptr),GFP_ATOMIC);
  no->st=buffer;
  no->next=lst;

  lst=no;
  return no;
}


t_ptr *krlista_apaga(t_ptr *lst, void *buffer){
  t_ptr *no,*no_aux;

    no=lst;
    if ((no->st)==buffer){
      no_aux=lst;
      lst=lst->next;
      kfree(no_aux);
    }else if (no->next->st==buffer){
      no_aux=(no)->next;
      (no)->next=(no_aux)->next;
      kfree(no_aux);   
    }else{
      while ((no->next->st!=buffer)&&(no->next !=0)){
        no=no->next;
      }
      if (no->next){
        no_aux=no->next;
        no->next=no->next->next;
        kfree(no_aux);
      }   
    }
 
  return lst;
}

int krlista_destroi(t_ptr *lst) {
  t_ptr *prev;

  if(lst) {
    prev=lst;
    lst=lst->next;

    while(lst!=NULL) {
      kfree(prev->st);    
      kfree(prev);    
      prev=lst;
      lst=lst->next;   
    }
    kfree(prev->st);    
    kfree(prev);    
  }

  return 1;
}
