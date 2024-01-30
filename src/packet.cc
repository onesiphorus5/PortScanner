#include "packet.h"

const uint16_t SRC_PORT = 4647;

uint16_t 
IP_packet::cksum16( const uint16_t* buffer, ssize_t len, 
                    uint32_t prev_sum ) const {
   int nleft = len;
   uint32_t sum = prev_sum;
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

/*
uint16_t
IP_packet::cksum_tcp() const {
   struct iphdr* pIph = _ip_hdr;
   unsigned short* ipPayload = (unsigned short*)_tcp_hdr;

    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    // struct in_addr saddr;
    struct in_addr saddr2;
    // inet_aton( "192.168.1.71", &saddr );
    // pIph->saddr = saddr.s_addr;
    saddr2.s_addr = pIph->saddr;
    std::cout << "cksum saddr: " <<  inet_ntoa( saddr2 ) << std::endl;
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    // tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    // tcphdrp->check = (unsigned short)sum;
    return (unsigned short)sum;

}
*/

uint16_t 
IP_packet::cksum_tcp() const {
   struct TCP_pseudo_hdr pseudo_hdr;
   memset( &pseudo_hdr, 0, sizeof( pseudo_hdr ) );

   uint32_t sum = 0;

   sum += (_ip_hdr->saddr>>16)&0xFFFF;
   sum += (_ip_hdr->saddr)&0xFFFF;
   //the dest ip
   sum += (_ip_hdr->daddr>>16)&0xFFFF;
   sum += (_ip_hdr->daddr)&0xFFFF;
   //protocol and reserved: 6
   sum += htons(IPPROTO_TCP);
   //the length
   sum += htons( sizeof( struct tcphdr ) );

   // pseudo_hdr.src = _ip_hdr->saddr;
   // pseudo_hdr.dst = _ip_hdr->daddr;
   // pseudo_hdr.zero = 0;
   // pseudo_hdr.protocol = IPPROTO_TCP;
   // pseudo_hdr.len = htons( sizeof( struct tcphdr ) );
   // sum = cksum16( (uint16_t*)&pseudo_hdr, pseudo_hdr.size(), 0 );

   uint16_t checksum = cksum16( (uint16_t*)_tcp_hdr, sizeof( struct tcphdr ), sum );

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
   // std::cout << "Here" << std::endl;

   // Setup TCP header 
   struct tcphdr* tcpHeader = \
                     (struct tcphdr*) ( _buffer + sizeof( struct iphdr ) );
   tcpHeader->source  = htons( SRC_PORT );
   tcpHeader->dest    = dst_port;
   tcpHeader->seq     = 1234; // TODO: remove after debugging
   // tcpHeader->seq     = htonl( (uint32_t)rand() );
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
   // tcpHeader->check   = htons( 48116 ); // TODO: remove after testing
   tcpHeader->check   = cksum_tcp();

   std::cout << "tcp checksum: " << cksum_tcp() << std::endl;

   // TODO: the checksum is not correct (by looking at wireshark)
   /*
   if ( cksum_tcp() != 0 ) {
      std::cout << "TCP checksum error" << std::endl;
      exit( EXIT_FAILURE );
   }
   */
   std::cout << "TCP checksum: " << tcpHeader->check << std::endl;
}