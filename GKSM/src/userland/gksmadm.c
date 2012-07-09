#include <stdio.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "structs.h"

int main(int argc,char **argv)
{
    int fd;
    int err;
    unsigned int uid,port;
    t_gksm_up *bindpriv;

    if(argc < 3)  {
        printf("usage: %s <uid> <port>\n",argv[0]);
        return -1;
    }
    fd = open("/dev/gksm",O_RDONLY);
    if(fd<0) {
           printf("can't open device\n");
           return -1;
     }

     uid=atoi(argv[1]);
     port=atoi(argv[2]);

     printf("permit bind %d from %d\n", uid,port);
     bindpriv=(t_gksm_up*)malloc(sizeof(t_gksm_up));
     bindpriv->uid=uid;
     bindpriv->port=port;
     err=ioctl(fd,GKSM_ADDUIDPORT,bindpriv);
     printf("%d\n",err);
     free(bindpriv);
}
