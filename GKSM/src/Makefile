# $Id: Makefile,v 1.3 2002/06/03 20:09:42 mori Exp $
#  GenHex Kernel Security Module
#

INCLUDEDIR = /usr/include
CC = gcc

CFLAGS = -D_DEBUG_ -D__KERNEL__ -DMODULE -O3 -Wall -I$(INCLUDEDIR) -D_README_

OBJS = main.o  syscall.o listas/krlista.o ioctl.o

all:	$(OBJS)
	more DISCLAIMER
	$(LD) -r $^ -o gksm.o -noinhibit-exec

clean:
	rm -f *.o
	rm -f listas/*.o

