/*
Name: Nathan Shull
Net-id: nshull16
Spring 2020
Date of Submission:4-20-20
*/
#define RETSIGTYPE void

#include <sys/types.h>

#include <sys/time.h>

#include <netinet/in.h>

#include <pcap.h>

#include <signal.h>

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <ctype.h>

# ifndef setsignal_h
# define setsignal_h

RETSIGTYPE( * setsignal(int, RETSIGTYPE( * )(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char * user,
  const struct pcap_pkthdr * h,
    const u_char * p);

int packettype;

char * program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program * , int);

extern char * copy_argv(char ** );

extern int optind;
extern int opterr;
extern char * optarg;
int pflag = 0, aflag = 0, ip_count = 0, arp_count = 0, icmp_count = 0, dns_count = 0, tcp_count = 0, smtp_count = 0, pop_count = 0, imap_count = 0, http_count = 0;

/* Forwards */
void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t * pd;

extern int optind;
extern int opterr;
extern char * optarg;
//int pflag = 0, aflag = 0;

int
main(int argc, char ** argv) {
  int cnt, op, i, done = 0;
  bpf_u_int32 localnet, netmask;
  char * cp, * cmdbuf, * device;
  struct bpf_program fcode;
  void( * oldhandler)(int);
  u_char * pcap_userdata;
  char ebuf[PCAP_ERRBUF_SIZE];

  cnt = -1;
  device = NULL;

  if ((cp = strrchr(argv[0], '/')) != NULL)
    program_name = cp + 1;
  else
    program_name = argv[0];

  opterr = 0;
  while ((i = getopt(argc, argv, "pa")) != -1) {
    switch (i) {
    case 'p':
      pflag = 1;
      break;
    case 'a':
      aflag = 1;
      break;
    case '?':
    default:
      done = 1;
      break;
    }
    if (done) break;
  }
  if (argc > (optind)) cmdbuf = copy_argv( & argv[optind]);
  else cmdbuf = "";

  if (device == NULL) {
    device = pcap_lookupdev(ebuf);
    if (device == NULL)
      error("%s", ebuf);
  }
  pd = pcap_open_live(device, snaplen, 1, 1000, ebuf);
  if (pd == NULL)
    error("%s", ebuf);
  i = pcap_snapshot(pd);
  if (snaplen < i) {
    warning("snaplen raised from %d to %d", snaplen, i);
    snaplen = i;
  }
  if (pcap_lookupnet(device, & localnet, & netmask, ebuf) < 0) {
    localnet = 0;
    netmask = 0;
    warning("%s", ebuf);
  }
  /*
   * Let user own process after socket has been opened.
   */
  setuid(getuid());

  if (pcap_compile(pd, & fcode, cmdbuf, 1, netmask) < 0)
    error("%s", pcap_geterr(pd));

  (void) setsignal(SIGTERM, program_ending);
  (void) setsignal(SIGINT, program_ending);
  /* Cooperate with nohup(1) */
  if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
    (void) setsignal(SIGHUP, oldhandler);

  if (pcap_setfilter(pd, & fcode) < 0)
    error("%s", pcap_geterr(pd));
  pcap_userdata = 0;
  (void) fprintf(stderr, "%s: listening on %s\n", program_name, device);
  if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
    (void) fprintf(stderr, "%s: pcap_loop: %s\n",
      program_name, pcap_geterr(pd));
    exit(1);
  }
  pcap_close(pd);
  exit(0);
}

/* routine is executed on exit */
void program_ending(int signo) {
  struct pcap_stat stat;
  printf("# IP Packets = %d\n", ip_count);
  printf("# ARP Packets = %d\n", arp_count);
  printf("# DNS Packets = %d\n", dns_count);
  printf("# ICMP Packets = %d\n", icmp_count);
  printf("# TCP Packets = %d\n", tcp_count);
  printf("# SMTP Packets = %d\n", smtp_count);
  printf("# POP Packets = %d\n", pop_count);
  printf("# IMAP Packets = %d\n", imap_count);
  printf("# HTTP Packets = %d\n", http_count);

  if (pd != NULL && pcap_file(pd) == NULL) {
    (void) fflush(stdout);
    putc('\n', stderr);
    if (pcap_stats(pd, & stat) < 0)
      (void) fprintf(stderr, "pcap_stats: %s\n",
        pcap_geterr(pd));
    else {
      (void) fprintf(stderr, "%d packets received by filter\n",
        stat.ps_recv);
      (void) fprintf(stderr, "%d packets dropped by kernel\n",
        stat.ps_drop);
    }
  }
  exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register
  const u_char * cp, register u_int length) {
  register u_int i, s;
  register int nshorts;

  nshorts = (u_int) length / sizeof(u_short);
  i = 0;
  while (--nshorts >= 0) {
    if ((i++ % 8) == 0)
      (void) printf("\n\t\t\t");
    s = * cp++;
    (void) printf(" %02x%02x", s, * cp++);
  }
  if (length & 1) {
    if ((i % 8) == 0)
      (void) printf("\n\t\t\t");
    (void) printf(" %02x", * cp);
  }
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register
  const u_char * bp, register u_int length) {
  register
  const u_short * sp;
  register u_int i;
  register int nshorts;

  if ((long) bp & 1) {
    default_print_unaligned(bp, length);
    return;
  }
  sp = (u_short * ) bp;
  nshorts = (u_int) length / sizeof(u_short);
  i = 0;
  while (--nshorts >= 0) {
    if ((i++ % 8) == 0)
      (void) printf("\n\t");
    (void) printf(" %04x", ntohs( * sp++));
  }
  if (length & 1) {
    if ((i % 8) == 0)
      (void) printf("\n\t");
    (void) printf(" %02x", *(u_char * ) sp);
  }
}

/*
insert your code in this routine

*/

void raw_print(u_char * user,
  const struct pcap_pkthdr * h,
    const u_char * p) {
  u_int length = h - > len;
  u_int caplen = h - > caplen;

  uint16_t e_type;
  printf("========Decoding Ethernet Header========\n");
  printf("Destination Address = %02x:%02x:%02x:%02x:%02x:%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
  printf("Source Address = %02x:%02x:%02x:%02x:%02x:%02x\n", p[6], p[7], p[8], p[9], p[10], p[11]);
  e_type = p[12] * 256 + p[13];
  if (e_type < 0x0600) {
    printf("Length = 0x%04x\n", e_type);
  } else {
    printf("Type = 0x%04x\n", e_type);
  }
  if (e_type == 0x0800) {
    ip_count++;
    printf("Payload = IPv4\n");
    printf("\t========Decoding IP Header========\n");
    printf("\tVersion Number = %d\n", p[14] >> 4);
    printf("\tHeader Length = %d bytes\n", (p[14] & 0x0F) * 4);
    printf("\tType of Service = %02x\n", p[15]);
    printf("\tTotal Length = %d bytes\n", p[16] * 256 + p[17]);
    printf("\tID = %04x\n", p[18] * 256 + p[19]);
    printf("\tFlags = %04x\n", p[20] * 256 + p[21]);
    if ((p[20] >> 6) & 0x01) {
      printf("\t   D Flag = Don't Fragment\n");
    }
    if ((p[20] >> 5) & 0x01) {
      printf("\t   M Flag = More Fragments\n");
    }
    printf("\tOffset = %d\n", (p[20] * 256 + p[21]) & 0x1FFF);
    printf("\tTTL = %d\n", p[22]);
    printf("\tProtocol = %d\n", p[23]);
    printf("\tChecksum = %04x\n", p[24] * 256 + p[25]);
    printf("\tSource IP Address = %d.%d.%d.%d\n", p[26], p[27], p[28], p[29]);
    printf("\tDestination IP Address = %d.%d.%d.%d\n", p[30], p[31], p[32], p[33]);
    if (((p[14] & 0x0F) * 4) > 20) {
      printf("\tIP Options Exist\n");
      printf("\tOptions = 0x");
      int n = 20;
      int m = (p[14] & 0x0F) * 4;
      for (n; n < m; n++) {
        printf("%02x", p[n]);
      }
    } else {
      printf("\tNo IP Options\n");
    }
    if (p[23] != 0x01 && p[23] != 0x06) {
      printf("\tIP Payload: 0x");
      int i = 34;
      for (i; i < caplen; i++) {
        printf("%02x", p[i]);
      }
      printf("\n");
    }

    if (p[23] == 0x01) {
      icmp_count++;
      int start_index = 14 + ((p[14] & 0x0F) * 4);
      printf("\t\t========Decoding ICMP Header========\n");
      printf("\t\tType = %d\n", p[start_index]);
      printf("\t\tCode = %d\n", p[start_index + 1]);
      printf("\t\tChecksum = 0x%02x%02x\n", p[start_index + 2], p[start_index + 3]);
      if (p[start_index] == 0x00) {
        printf("\t\tEcho Reply\n");
        printf("\t\tID = 0x%02x%02x\n", p[start_index + 4], p[start_index + 5]);
        printf("\t\tSequence Number = 0x%02x%02x\n", p[start_index + 6], p[start_index + 7]);
        printf("\t\tData = 0x");
        int j = start_index + 8;
        for (j; j < caplen; j++) {
          printf("%02x", p[j]);
        }
      } else if (p[start_index] == 0x03) {
        printf("\t\tDestination Unreachable\n");
        printf("\t\tParameter=0");
        printf("\t\tData = 0x");
        int j = start_index + 4;
        for (j; j < caplen; j++) {
          printf("%02x", p[j]);
        }
      } else if (p[start_index] == 0x05) {
        printf("\t\tRedirection\n");
        printf("\t\tIP Address of New Router = %d.%d.%d.%d\n", p[start_index + 4], p[start_index + 5], p[start_index + 6], p[start_index + 7]);
        printf("\t\tData = 0x");
        int j = start_index + 8;
        for (j; j < caplen; j++) {
          printf("%02x", p[j]);
        }
      } else if (p[start_index] == 0x08) {
        printf("\t\tEcho Request\n");
        printf("\t\tID = 0x%02x%02x\n", p[start_index + 4], p[start_index + 5]);
        printf("\t\tSequence Number = 0x%02x%02x\n", p[start_index + 6], p[start_index + 7]);
        printf("\t\tData = 0x");
        int j = start_index + 8;
        for (j; j < caplen; j++) {
          printf("%02x", p[j]);
        }
      } else if (p[start_index] == 0x0B) {
        printf("\t\tTime Exceeded\n");
        printf("\t\tParameter = 0");
        printf("\t\tData = 0x");
        int j = start_index + 4;
        for (j; j < caplen; j++) {
          printf("%02x", p[j]);
        }
      } else if (p[start_index] == 0x0D) {
        printf("\t\tTimestamp Request\n");
        printf("\t\tID = 0x%02x%02x\n", p[start_index + 4], p[start_index + 5]);
        printf("\t\tSequence Number = 0x%02x%02x\n", p[start_index + 6], p[start_index + 7]);
        printf("\t\tOriginal Timestamp = 0x%02x%02x%02x%02x\n", p[start_index + 8], p[start_index + 9], p[start_index + 10], p[start_index + 11]);
        printf("\t\tReceive Timestamp = 0x%02x%02x%02x%02x\n", p[start_index + 12], p[start_index + 13], p[start_index + 14], p[start_index + 15]);
        printf("\t\tTransmit Timestamp = 0x%02x%02x%02x%02x\n", p[start_index + 16], p[start_index + 17], p[start_index + 18], p[start_index + 19]);
      } else if (p[start_index] == 0x0E) {
        printf("\t\tTimestamp Reply\n");
        printf("\t\tID = 0x%02x%02x\n", p[start_index + 4], p[start_index + 5]);
        printf("\t\tSequence Number = 0x%02x%02x\n", p[start_index + 6], p[start_index + 7]);
        printf("\t\tOriginal Timestamp = 0x%02x%02x%02x%02x\n", p[start_index + 8], p[start_index + 9], p[start_index + 10], p[start_index + 11]);
        printf("\t\tReceive Timestamp = 0x%02x%02x%02x%02x\n", p[start_index + 12], p[start_index + 13], p[start_index + 14], p[start_index + 15]);
        printf("\t\tTransmit Timestamp = 0x%02x%02x%02x%02x\n", p[start_index + 16], p[start_index + 17], p[start_index + 18], p[start_index + 19]);
      }
    } else if (p[23] == 0x06) {
      tcp_count++;
      int start_index = 14 + ((p[14] & 0x0F) * 4);
      printf("\t\t========Decoding TCP Header========\n");
      printf("\t\tSource Port Number = %d\n", p[start_index] * 256 + p[start_index + 1]);
      printf("\t\tDestination Port Number = %d\n", p[start_index + 2] * 256 + p[start_index + 3]);
      printf("\t\tSequence Number = 0x%02x%02x%02x%02x\n", p[start_index + 4], p[start_index + 5], p[start_index + 6], p[start_index + 7]);
      printf("\t\tAcknowledgement Number = 0x%02x%02x%02x%02x\n", p[start_index + 8], p[start_index + 9], p[start_index + 10], p[start_index + 11]);
      printf("\t\tHeader Length = %d bytes\n", (p[start_index + 12] >> 4) * 4);
      printf("\t\tReserved = %d\n", (p[start_index + 12] & 0x0E) >> 1);
      printf("\t\tFlags = %02x\n", p[start_index + 13]);
      if ((p[start_index + 13] >> 7) && 0x01) {
        printf("\t\tCWR: Set\n");
      } else if ((p[start_index + 13] >> 6) && 0x01) {
        printf("\t\tECN-Echo: Set\n");
      } else if ((p[start_index + 13] >> 5) && 0x01) {
        printf("\t\tUrgent: Set\n");
      } else if ((p[start_index + 13] >> 4) && 0x01) {
        printf("\t\tAcknowledgement: Set\n");
      } else if ((p[start_index + 13] >> 3) && 0x01) {
        printf("\t\tPush: Set\n");
      } else if ((p[start_index + 13] >> 2) && 0x01) {
        printf("\t\tReset: Set\n");
      } else if ((p[start_index + 13] >> 1) && 0x01) {
        printf("\t\tSyn: Set\n");
      } else if ((p[start_index + 13] >> 0) & 0x01) {
        printf("\t\tFin: Set\n");
      }
      if (((p[start_index + 12] >> 4) * 4) > 20) {
        printf("\t\tTCP Options Exist\n");
        printf("\t\tOptions = 0x");
        int k = start_index + 20;
        int l = (p[start_index + 12] >> 4) * 4;
        for (k; k < start_index + l; k++) {
          printf("%02x", p[k]);
        }
        printf("\n");
      } else {
        printf("\t\tNo TCP Options Exist\n");
      }
      if ((p[34] * 256 + p[35]) == 0x0035 || p[36] * 256 + p[37] == 0x0035) {
        printf("\t\tDNS Packet Found\n");
        dns_count++;
      }
      //POP
      if ((p[34] >> 8) + p[35] == 0x6E || (p[36] >> 8) + p[37] == 0x6E) {
        pop_count++;
        printf("\t\tPOP Payload: ");
        int i = 53;
        const u_char * pointer = 54 + p;
        for (i = 53; i < length; i++, pointer++) {
          if (isprint( * pointer) != 0) {
            printf("%c", * pointer);
          }
        }
        printf("\n");
      }
      //SMTP
      if ((p[34] >> 8) + p[35] == 0x19 || (p[36] >> 8) + p[37] == 0x19) {
        smtp_count++;
        printf("\t\tSMTP Payload: ");
        int i = 53;
        const u_char * pointer = 54 + p;
        for (i = 53; i < length; i++, pointer++) {
          if (isprint( * pointer) != 0) {
            printf("%c", * pointer);
          }
        }
        printf("\n");
      }
      //IMAP
      if ((p[34] >> 8) + p[35] == 0x8F || (p[36] >> 8) + p[37] == 0x8F) {
        imap_count++;
        printf("\t\tIMAP Payload: ");
        int i = 53;
        const u_char * pointer = 54 + p;
        for (i = 53; i < length; i++, pointer++) {
          if (isprint( * pointer) != 0) {
            printf("%c", * pointer);
          }
        }
        printf("\n");
      }
      //HTTP
      if ((p[34] >> 8) + p[35] == 0x50 || (p[36] >> 8) + p[37] == 0x50) {
        http_count++;
        printf("\t\tHTTP Payload: ");
        int i = 53;
        const u_char * pointer = 54 + p;
        for (i = 53; i < length; i++, pointer++) {
          if (isprint( * pointer) != 0) {
            printf("%c", * pointer);
          }
        }
        printf("\n");
      }
      if ((p[34] >> 8) + p[35] != 0x50 || (p[36] >> 8) + p[37] != 0x50 || (p[34] >> 8) + p[35] != 0x8F || (p[36] >> 8) + p[37] != 0x8F || (p[34] >> 8) + p[35] != 0x19 || (p[36] >> 8) + p[37] != 0x19 || (p[34] >> 8) + p[35] != 0x6E || (p[36] >> 8) + p[37] != 0x6E) {
        printf("\t\tTCP Payload: 0x");
        int i = 54;
        for (i; i < caplen; i++) {
          printf("%02x", p[i]);
        }
        printf("\n");
      }

    } else if (p[23] == 0x11) {
      printf("\t\t========Decoding UDP Header========\n");
      if ((p[34] * 256 + p[35]) == 0x0035 || p[36] * 256 + p[37] == 0x0035) {
        printf("\t\tDNS Packet Found\n");
        dns_count++;
      }
    }

  } else if (e_type == 0x0806) {
    arp_count++;
    printf("Payload = ARP\n");
    uint16_t r_type;
    r_type = p[21];
    printf("\t========Decoding ARP Header========\n");
    printf("\tHardware Type = Ethernet with a value of 1\n");
    printf("\tProtocol Type = 0x%02x%02x\n", p[16], p[17]);
    printf("\tHardware Length = %02x\n", p[18]);
    printf("\tProtocol Length = %02x\n", p[19]);
    printf("\tOperation type is a ");
    if (r_type == 0x01) {
      printf("request");
    } else {
      printf("reply");
    }
    printf("\n");
    printf("\tSender Hardware Address = %02x:%02x:%02x:%02x:%02x:%02x\n", p[22], p[23], p[24], p[25], p[26], p[27]);
    printf("\tSender Protocol Address = %d.%d.%d.%d\n", p[28], p[29], p[30], p[31]);
    printf("\tTarget Hardware Address = %02x:%02x:%02x:%02x:%02x:%02x\n", p[32], p[33], p[34], p[35], p[36], p[37]);
    printf("\tTarget Protocol Address = %d.%d.%d.%d\n", p[38], p[39], p[40], p[41]);
    printf("\tARP Payload: 0x");
    int i = 43;
    for (i; i < caplen; i++) {
      printf("%02x", p[i]);
    }
    printf("\n");
  }

  default_print(p, caplen);
  putchar('\n');
}