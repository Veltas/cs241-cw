#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <stdlib.h>

struct Eth_header {
  u_char  dest_mac[6],
          src_mac[6];
  u_short type;
};

#define ETH_TYPE_IPV4 0x0800 // IPv4 protocol number

struct IP_header {
  u_char  v_hl, // High nibble: version. Low nibble: header_length.
          dscp_ecn; // High 6 bits: DSCP, low 2 bits: ECN.
  u_short length,
          id,
          df_mf_offset; // Contains flags (DF, MF) and offset
  u_char  ttl,
          protocol;
  u_short checksum;
  u_char  src_ip[4],
          dest_ip[4],
          option_data[];
};

#define IHL_MULTIPLIER 4     // header_length measures in 32-bit chunks
#define IHL_MIN        20    // Minimum IHL
#define IP_TYPE_TCP    0x06u // TCP protocol number

struct TCP_header {
  u_short src_port,
          dest_port;
  u_int   number,
          ack_number;
  u_char  offset_nsbit, // High nibble: data offset, 0, low bit: NS flag
          flags;
  u_short window_size,
          checksum,
          urgent_ptr;
  u_char  option_data[];
};

#define TCP_HEADER_MIN 20 // Minimum TCP header length

// tcp_header.flags flag values
enum {
  TCP_CWR = 0x80,
  TCP_ECE = 0x40,
  TCP_URG = 0x20,
  TCP_ACK = 0x10,
  TCP_PSH = 0x08,
  TCP_RST = 0x04,
  TCP_SYN = 0x02,
  TCP_FIN = 0x01
};

// Loads ethernet header information, returns true on error
static int interpret_eth(
  struct Eth_header *const        eth_hdr,
  const struct pcap_pkthdr *const header,
  const unsigned char *const      packet,
  const int                       verbose
) {
  if (header->len < ETH_HLEN) {
    if (verbose) printf("analysis: Packet too small for ethernet header\n");
    return 1;
  }

  // Copy header info over
  *eth_hdr = *(const struct Eth_header *)packet;

  // Adjust for endianness
  eth_hdr->type = ntohs(eth_hdr->type);

  return 0;
}

// Loads IPv4 header information, returns true on error
static int interpret_ip(
  const struct Eth_header *const  eth_hdr,
  struct IP_header *const         ip_hdr,
  const struct pcap_pkthdr *const header,
  const unsigned char *const      packet,
  const int                       verbose,
  const size_t                    ip_hdr_d // header displacement/offset
) {
  // Sanity checks on the ethernet header, and pcap packet size
  if (eth_hdr->type != ETH_TYPE_IPV4) {
    if (verbose) printf("analysis: Ethernet packet not trafficking IPv4\n");
    return 1;
  }
  if (header->len < ip_hdr_d + IHL_MIN) {
    printf("analysis: Packet too small for IPv4 header\n");
    return 1;
  }

  // Copy IPv4 header over
  *ip_hdr = *(const struct IP_header *)(packet + ip_hdr_d);

  // Correct endianness
  ip_hdr->length   = ntohs(ip_hdr->length);
  ip_hdr->id       = ntohs(ip_hdr->id);
  ip_hdr->checksum = ntohs(ip_hdr->id);

  // Some sanity checks on the header
  const u_char ip_version = ip_hdr->v_hl >> 4;
  const u_char ip_hdr_len = (ip_hdr->v_hl & 0xF) * IHL_MULTIPLIER;
  if (ip_version != 4) {
    if (verbose) printf("analysis: Expected IPv4, got IPv%d\n", ip_version);
    return 1;
  }
  if (ip_hdr_len < IHL_MIN) {
    if (verbose) printf("analysis: IP header has bad header length\n");
    return 1;
  }

  return 0;
}

static int interpret_tcp(
  const struct IP_header *const   ip_hdr,
  struct TCP_header *const        tcp_hdr,
  const struct pcap_pkthdr *const header,
  const unsigned char *const      packet,
  const int                       verbose,
  const size_t                    tcp_hdr_d // header displacement/offset
) {
  // Sanity checks
  if (ip_hdr->protocol != IP_TYPE_TCP) {
    if (verbose) printf("analysis: IPv4 packet not trafficking TCP\n");
    return 1;
  }
  if (header->len < tcp_hdr_d + TCP_HEADER_MIN) {
    if (verbose) printf("analysis: Packet too small for TCP header\n");
    return 1;
  }

  // Copy over TCP header
  *tcp_hdr = *(const struct TCP_header *)(packet + tcp_hdr_d);

  // Correct endianness
  tcp_hdr->src_port    = ntohs(tcp_hdr->src_port);
  tcp_hdr->dest_port   = ntohs(tcp_hdr->src_port);
  tcp_hdr->number      = ntohl(tcp_hdr->number);
  tcp_hdr->ack_number  = ntohl(tcp_hdr->ack_number);
  tcp_hdr->window_size = ntohs(tcp_hdr->window_size);
  tcp_hdr->checksum    = ntohs(tcp_hdr->checksum);
  tcp_hdr->urgent_ptr  = ntohs(tcp_hdr->urgent_ptr);

  return 0;
}

// Interpret relevant headers from pcap packet and analyse for malicious
// activity
void analyse(
  const struct pcap_pkthdr *const header,
  const unsigned char *const      packet,
  const int                       verbose
) {
  // Interpret ethernet header (if possible), or stop
  struct Eth_header eth_hdr;
  if (interpret_eth(&eth_hdr, header, packet, verbose)) return;

  // Check for 

  // Interpret IPv4 header (if possible), or stop
  size_t next_header = ETH_HLEN;
  struct IP_header ip_hdr;
  if (interpret_ip(&eth_hdr, &ip_hdr, header, packet, verbose, next_header)) {
    return;
  }

  // Interpret TCP header (if possible), or stop
  next_header += (ip_hdr.v_hl && 0xF) * IHL_MULTIPLIER;
  struct TCP_header tcp_hdr;
  if (interpret_tcp(&ip_hdr, &tcp_hdr, header, packet, verbose, next_header)) {
    return;
  }
}
