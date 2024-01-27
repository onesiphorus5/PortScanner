#include "packet.h"

const uint16_t SRC_PORT = 4647;

void setup_packet( const struct sockaddr_in *target, IP_packet& ip_packet ) {
   uint32_t src_addr = localhost_addr.sin_addr.s_addr;
   uint32_t dst_addr = target->sin_addr.s_addr;
   uint16_t dst_port = target->sin_port;

   // Setup TCP header 
   struct tcphdr tcpHeader;
   memset( &tcpHeader, 0, sizeof( struct tcphdr ) );
   tcpHeader.source  = htons( SRC_PORT );
   tcpHeader.dest    = dst_port;
   tcpHeader.seq     = htonl( (uint32_t)rand() );
   tcpHeader.ack_seq = 0;
   tcpHeader.doff    = uint8_t( sizeof( struct tcphdr ) / 4 );
   tcpHeader.urg     = 0;
   tcpHeader.ack     = 0;
   tcpHeader.psh     = 0;
   tcpHeader.rst     = 0;
   tcpHeader.syn     = 1;
   tcpHeader.fin     = 0;
   tcpHeader.window  = htons( 65535 ); // max size: 2^16-1
   tcpHeader.check   = 0;
   tcpHeader.urg_ptr = 0;

   // Setup IP header
   struct iphdr  ipHeader;
   memset( &ipHeader, 0, sizeof( struct iphdr ) );
   ipHeader.version  = 4; // IPv4
   ipHeader.ihl      = 5; // 5 32-bit words
   ipHeader.tos      = 0;
   ipHeader.tot_len  = htons( sizeof( struct iphdr) + sizeof( struct tcphdr ) );
   ipHeader.id       = htons( (uint16_t)rand() );
   ipHeader.frag_off = htons( uint16_t( 1 << 14 ) ); // Don't fragment
   ipHeader.ttl      = 64; // Linux default ttl value
   ipHeader.protocol = IPPROTO_TCP;
   ipHeader.check    = 0;
   ipHeader.saddr    = src_addr;
   ipHeader.daddr    = dst_addr;
  
   // Set checksum for both headers
   ip_packet.ip_hdrIs( ipHeader );
   ip_packet.set_ipHeaderChecksum();
   ip_packet.tcp_hdrIs( tcpHeader );
   ip_packet.set_tcpHeaderChecksum();
}

void parse_packet( const char*, ssize_t, const ScanRequest& scan_request, 
                  IP_packet& ip_packet ) {

   // TODO: implement missing
}