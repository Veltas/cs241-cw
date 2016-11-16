#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void analyse(struct pcap_pkthdr *header __attribute__ ((unused)),
             const unsigned char *packet __attribute__ ((unused)),
             int verbose __attribute__ ((unused)))
{
  // TODO your part 2 code here
}
