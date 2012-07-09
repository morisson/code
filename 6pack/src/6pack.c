/* 
 * 6pack - IPv6 HalfOpen Port Scanner
 * (C) 2003 Bruno Morisson <morisson@genhex.org>
 *
 * This code sucks, but works.
 *
 * $Id: 6pack.c,v 1.3 2004/02/10 22:55:56 mori Exp $
 */

#include <libnet.h>
#include <pcap.h>
#include <sys/time.h>
#include <signal.h>


int verbose = 0;
int timeout = 5;

void *
finish (int sig)
{
  printf ("\n");
  exit (0);
}


int
collect (char *iface, u_long seq)
{
  struct libnet_tcp_hdr *tcp;
  pid_t pid;
  struct pcap_pkthdr hdr;
  pcap_t *desc;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_char *in_pkt;
  struct bpf_program bp;
  char *filter = "ip6 and tcp";
  struct timeval timenow, timethen;
  int hdr_size;

  desc = pcap_open_live (iface, 1500, 1, 0, errbuf);
  if (desc == NULL)
    {
      fprintf (stderr, "error opening device for capture: %s", errbuf);
      return 0;
    }
  pcap_compile (desc, &bp, filter, 1, 65535);
  pcap_setfilter (desc, &bp);
  switch (pcap_datalink (desc))
    {
    case DLT_RAW:
      hdr_size = 40;
      if (verbose)
	printf ("Datalink: Raw\n");
      break;
    case DLT_EN10MB:
      hdr_size = 54;
      if (verbose)
	printf ("Datalink: Ethernet\n");
      break;
    default:
      fprintf (stderr, "Datalink type not supported\n");
      return 0;

    }

  if ((pid = fork ()))
    {				/*chld */
      setsid ();
      signal (SIGALRM, (void *) (finish));
      if (verbose)
	gettimeofday (&timethen, NULL);
      do
	{
	  alarm (timeout);
	  in_pkt = (u_char *) pcap_next (desc, &hdr);
	  if (in_pkt != NULL)
	    { /* we should check for extra headers...someday */
	      tcp = ((struct libnet_tcp_hdr *) (in_pkt + hdr_size));
	      if (ntohl (tcp->th_ack) == seq + 1)
		{
		  alarm (0);
		  if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK))
		    {
		      if (verbose)
			gettimeofday (&timenow, NULL);
		      !verbose ? printf ("Open: %d\n",
					 ntohs (tcp->
						th_sport)) :
			printf ("Open: %d  %u.%.4us\n",
				ntohs (tcp->th_sport),
				timenow.tv_sec - timethen.tv_sec,
				timenow.tv_usec - timethen.tv_usec);
		    }
		}
	    }
	}
      while (1);
    }
  return 1;
}


libnet_ptag_t
build_pkt (libnet_t * l, u_long * seq, struct libnet_in6_addr src,
	   struct libnet_in6_addr victim)
{

  libnet_ptag_t ip_tag, tcp_tag;

  ip_tag = tcp_tag = LIBNET_PTAG_INITIALIZER;
  libnet_seed_prand (l);

  *seq = (u_long) libnet_get_prand (LIBNET_PRu32);

  tcp_tag = libnet_build_tcp (0,
			      0,
			      *seq,
			      libnet_get_prand (LIBNET_PRu32),
			      TH_SYN,
			      libnet_get_prand (LIBNET_PRu16),
			      0, 0, LIBNET_TCP_H, NULL, 0, l, 0);

  ip_tag = libnet_build_ipv6 (0,
			      0,
			      LIBNET_TCP_H,
			      IPPROTO_TCP, 64, src, victim, NULL, 0, l, 0);
  return tcp_tag;
}



void
send_tcp_pkts (libnet_t * l, libnet_plist_t * plist, libnet_ptag_t tcp_tag,
	       u_long seq)
{

  int i;
  u_short bport, eport;

  while (libnet_plist_chain_next_pair (plist, &bport, &eport)
	 && (bport <= eport) && (bport))
    for (i = bport; i <= eport; i++)
      {
	tcp_tag = libnet_build_tcp (libnet_get_prand (LIBNET_PRu16),
				    i,
				    seq,
				    libnet_get_prand (LIBNET_PRu32),
				    TH_SYN,
				    libnet_get_prand (LIBNET_PRu16),
				    0, 0, LIBNET_TCP_H, NULL, 0, l, tcp_tag);
	libnet_write (l);
	usleep (1); /* kernel buffers will prevent high rate packet injection
                     *  unless we sleep for a while (1usec is enough)
                     * There are cleaner ways of doing this... see libdnet
                     */
      }
}

void
usage ()
{
  printf ("usage: ./6pack [options] -s <src> -d <dst> -p <portlist>\n");
  printf ("Options:\n");
  printf (" -i <interface> : interface on which to send the packets.\n");
  printf (" -v             : be more verbose.\n");
  printf
    (" -t <seconds>   : time to wait for next packet before quitting. Default 5secs.\n");
  exit (0);
}

int
main (int argc, char **argv)
{
  libnet_t *l;
  char err_buf[LIBNET_ERRBUF_SIZE];
  char *iface = NULL;
  char *src_s = NULL, *victim_s = NULL, *plist_s = NULL;
  libnet_plist_t *plist=NULL;
  struct libnet_in6_addr src, victim;
  int s = 0, d = 0, i = 0, p = 0, opt;
  libnet_ptag_t tcp_tag;
  u_long seq;
  extern char *optarg;
  extern int opterr;

  printf
    ("\n6pack - IPv6 Port Scanner - v0.0002 ( http://genhex.org/projects/6pack/ )\n(c) 2003 Bruno Morisson <morisson@genhex.org>\n\n");

  while ((opt = getopt (argc, argv, "vTUb:t:i:p:s:d:")) != -1)
    {
      switch (opt)
	{
	case 's':
	  if (s)
	    usage ();
	  src_s = optarg;
	  s++;
	  break;
	case 'd':
	  if (d)
	    usage ();
	  victim_s = optarg;
	  d++;
	  break;
	case 'i':
	  if (i)
	    usage ();
	  iface = optarg;
	  i++;
	  break;
	case 'p':
	  if (p)
	    usage ();
	  plist_s = optarg;
	  p++;
	  break;
	case 'v':
	  verbose++;
	  break;
	case 't':
	  timeout = atoi (optarg);
	  break;
	default:
	  usage ();
	}
    }
  if (d != 1 || p != 1)
    usage ();

  if (!(l = libnet_init (LIBNET_RAW6, iface, err_buf)))
    {
      fprintf (stderr, "error opening raw sock: %s\n", err_buf);
      exit (-1);
    }
  if (!iface)
    iface = libnet_getdevice (l);
  if (libnet_plist_chain_new (l, &plist, plist_s) == -1)
    {
      fprintf (stderr, "invalid portlist %s\n", libnet_geterror (l));
      exit (-1);
    }

  if(s) 
   src = libnet_name2addr6 (l, src_s, LIBNET_RESOLVE);
  else 
   src = libnet_get_ipaddr6(l);

  if (!memcmp
      ((char *) &src, (char *) &in6addr_error, sizeof (in6addr_error)))
    {
      fprintf (stderr, "error in address: %s\n", libnet_geterror (l));
      exit (-1);
    }
  
  victim = libnet_name2addr6 (l, victim_s, LIBNET_RESOLVE);
  if (!memcmp
      ((char *) &victim, (char *) &in6addr_error, sizeof (in6addr_error)))
    {
      fprintf (stderr, "error in address: %s\n", libnet_geterror (l));
      exit (-1);
    }


  printf ("Using device: %s\n", iface);

  tcp_tag = build_pkt (l, &seq, src, victim);

  signal (SIGCHLD, SIG_IGN); /* We really shouldn't do this... */
  if (!collect (iface, seq))
    return -1;

  printf ("Scanning ports %s on %s\n",
	  libnet_plist_chain_dump_string (plist), victim_s);
  send_tcp_pkts (l, plist, tcp_tag, seq);

  return 0;
}
