#include "packet.h"

const uint16_t SRC_PORT = 4647;

uint16_t 
IP_packet::cksum16( const uint16_t* buffer, ssize_t len, 
                    uint16_t prev_cksum ) const {
   int nleft = len;
   uint32_t sum = ~prev_cksum;
   const uint16_t *w = buffer;
   uint16_t answer = 0;

   /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
   while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
   }
   /* mop up an odd byte, if necessary */
   if (nleft == 1) {
      * (unsigned char *) (&answer) = * (unsigned char *) w;
      sum += answer;
   }
   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
   sum += (sum >> 16); /* add carry */
   answer = ~sum; /* truncate to 16 bits */

   return (answer);
}

uint16_t 
IP_packet::cksum_tcp() const {
   struct TCP_pseudo_hdr pseudo_hdr;
   memset( &pseudo_hdr, 0, sizeof( pseudo_hdr ) );

   pseudo_hdr.src = _ip_hdr->saddr;
   pseudo_hdr.dst = _ip_hdr->daddr;
   pseudo_hdr.zero = 0;
   pseudo_hdr.protocol = IPPROTO_TCP;
   pseudo_hdr.len = htons( sizeof( struct tcphdr ) );

   uint16_t sum = cksum16( (uint16_t*)&pseudo_hdr, pseudo_hdr.size(), 0 );
   sum = cksum16( (uint16_t*)_tcp_hdr, sizeof( struct tcphdr ), sum );

   return sum;
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
   ipHeader->saddr    = INADDR_ANY; // The kernel will set it
   ipHeader->daddr    = dst_addr;
   ip_hdrIs( ipHeader );
   // std::cout << "Here" << std::endl;

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

   // TODO: the checksum is not correct (by looking at wireshark)
   std::cout << "tcp size: " << sizeof( struct tcphdr ) << std::endl;
   if ( cksum_tcp() != 0 ) {
      std::cout << "TCP checksum error" << std::endl;
      exit( EXIT_FAILURE );
   }
   std::cout << "TCP checksum: " << tcpHeader->check << std::endl;
}