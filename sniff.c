#include "sniff.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "dispatch.h"

// Utility/Debugging method for dumping raw packet data
static void dump(const unsigned char *const data, const size_t length) {
  size_t i;
  static size_t pcount = 0;
  // Decode Packet Header
  const struct ether_header *const eth_header = (const void *)data;
  printf("\n\n === PACKET %zu HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %zu DATA ==\n", pcount);
  // Decode Packet Data (Skipping over the header)
  if (length > ETH_HLEN) {
    size_t data_bytes = length - ETH_HLEN;
    const unsigned char *payload = data + ETH_HLEN;
    static const size_t output_sz = 20; // Output this many bytes at a time
    while (data_bytes > 0) {
      const size_t output_bytes =
        data_bytes < output_sz ? data_bytes : output_sz;
      // Print data in raw hexadecimal form
      for (i = 0; i < output_sz; ++i) {
        if (i < output_bytes) {
          printf("%02x ", payload[i]);
        } else {
          printf ("   "); // Maintain padding for partial lines
        }
      }
      printf ("| ");
      // Print data in ascii form
      for (i = 0; i < output_bytes; ++i) {
        const char byte = payload[i];
        if (isprint(byte)) {
          // Byte is in printable ascii range
          printf("%c", byte);
        } else {
          printf(".");
        }
      }
      printf("\n");
      payload += output_bytes;
      data_bytes -= output_bytes;
    }
  }
  pcount++;
}

// Application main sniffing loop
void sniff(const char *const interface, const int verbose) {
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *const pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  printf("SUCCESS! Opened %s for capture\n", interface);
  // Capture packets (very ugly code)
  while (1) {
    // Capture a packet
    struct pcap_pkthdr header;
    const unsigned char *const packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // Optional: dump raw data to terminal
      if (verbose) {
        dump(packet, header.len);
      }
      // Dispatch packet for processing
      dispatch(&header, packet, verbose);
    }
  }
}
