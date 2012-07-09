#ifndef __KRLISTA_H
#define __KRLISTA_H

#include "../incs.h" 


typedef struct s_no {
    void *st;
    struct s_no *next;
} t_ptr;



/*---------fim tipos---------*/

t_ptr *krlista_insere(t_ptr *, void *);
t_ptr *krlista_apaga(t_ptr *, void *);
int krlista_destroi(t_ptr *);


#endif
