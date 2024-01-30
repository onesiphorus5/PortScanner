#include "packet.h"

const uint16_t SRC_PORT = 4647;

uint16_t 
IP_packet::cksum16( const uint16_t* buffer, ssize_t len, 
                    uint32_t prev_sum ) const {
   int nleft = len;
   uint32_t sum = prev_sum;

   while (nleft > 1) {
      sum += *buffer++;
      nleft -= 2;
   }
   if (nleft == 1) {
      sum += *(uint8_t*)buffer;
   }

   // In case there are carry over bits
   while ( sum >> 16 ) {
      sum = (sum >> 16) + (sum & 0XFFFF);
   }

   sum = ~sum;
   return (uint16_t)sum;
}

uint16_t 
IP_packet::cksum_tcp() const {
   uint32_t sum = 0;

   // TCP pseudo header
   sum += (_ip_hdr->saddr>>16)&0xFFFF;
   sum += (_ip_hdr->saddr)&0xFFFF;
   // -- the dest ip
   sum += (_ip_hdr->daddr>>16)&0xFFFF;
   sum += (_ip_hdr->daddr)&0xFFFF;
   // -- protocol and reserved
   sum += htons(IPPROTO_TCP);
   // -- the length
   sum += htons( sizeof( struct tcphdr ) );

   uint16_t checksum = \
               cksum16( (uint16_t*)_tcp_hdr, sizeof( struct tcphdr ), sum );

   return checksum;
}

void IP_packet::setup_packet( const struct sockaddr_in *target ) {
   uint32_t dst_addr = target->sin_addr.s_addr;
   uint16_t dst_port = target->sin_port;

   // Setup IP header
   struct iphdr* ipHeader = (struct iphdr*) _buffer;
   ipHeader->version  = 4; // IPv4
   ipHeader->ihl      = 5; // 5 32-bit words
   ipHeader->tos      = 0;
   ipHeader->tot_len  = htons( sizeof( struct iphdr) + sizeof( struct tcphdr ) );
   ipHeader->id       = 0; // The kernel will set it
   ipHeader->frag_off = htons( uint16_t( 1 << 14 ) ); // Don't fragment
   ipHeader->ttl      = 64; // Linux default ttl value
   ipHeader->protocol = IPPROTO_TCP;
   ipHeader->check    = 0;          // The kernel always sets it
   ipHeader->saddr    = localhost_addr.sin_addr.s_addr;
   ipHeader->daddr    = dst_addr;
   ip_hdrIs( ipHeader );

   // Setup TCP header 
   struct tcphdr* tcpHeader = \
                     (struct tcphdr*) ( _buffer + sizeof( struct iphdr ) );
   tcpHeader->source  = htons( SRC_PORT );
   tcpHeader->dest    = dst_port;
   tcpHeader->seq     = htonl( (uint32_t)rand() );
   tcpHeader->ack_seq = 0;
   tcpHeader->doff    = uint8_t( sizeof( struct tcphdr ) / 4 );
   tcpHeader->urg     = 0;
   tcpHeader->ack     = 0;
   tcpHeader->psh     = 0;
   tcpHeader->rst     = 0;
   tcpHeader->syn     = 1;
   tcpHeader->fin     = 0;
   tcpHeader->window  = htons( 65535 ); // max size: 2^16-1
   tcpHeader->check   = 0;
   tcpHeader->urg_ptr = 0;
   tcp_hdrIs( tcpHeader );
   tcpHeader->check   = cksum_tcp();

   // Verify that the checksum is correct
   if ( cksum_tcp() != 0 ) {
      std::cout << "TCP checksum error" << std::endl;
      exit( EXIT_FAILURE );
   }
}