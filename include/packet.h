#ifndef parket_h
#define parket_h

#include "cmdline_parser.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

// localhost_addr is set in main.cc
extern struct sockaddr_in localhost_addr;

class IP_packet{
private:
   struct tcphdr _tcp_hdr;
   struct iphdr  _ip_hdr;
   char* _buffer;

   // helper function
   uint16_t compute_checksum( const char* header, ssize_t hdr_size ) {
      uint32_t sum = 0;
      ssize_t hdr_size_16bit = hdr_size >> 2;
      uint16_t* header_16bit = (uint16_t*)header;
      for ( int i=0; i < hdr_size_16bit; ++i ) {
         sum += *( header_16bit + i );
      }
      // In case there is a carry over
      while( sum >> 16 ) {
         sum = (uint16_t)sum + (sum >> 16 );
      }

      return (uint16_t) ( ~sum );
   }

public:
   IP_packet() { _buffer = new char[size()]; }
   ~IP_packet() { delete[] _buffer; }

   void tcp_hdrIs( const struct tcphdr& hdr ) { 
      _tcp_hdr = hdr;
   }
   void ip_hdrIs( const struct iphdr& hdr ) { 
      _ip_hdr = hdr;
   }

   void set_ipHeaderChecksum() {
      _ip_hdr.check = compute_checksum( (const char*)&_ip_hdr, 
                                         sizeof( struct iphdr ) );
   }

   void set_tcpHeaderChecksum() {
      uint32_t checksum = 0;

      // TCP pseudo header checksum
      checksum += ( _ip_hdr.saddr >> 16 ) + (uint16_t)_ip_hdr.saddr;
      checksum += ( _ip_hdr.daddr >> 16 ) + (uint16_t)_ip_hdr.daddr;
      checksum += htons( (uint16_t) IPPROTO_TP );
      checksum += htons( sizeof( struct tcphdr ) );

      // TCP header checksum
      ssize_t tcp_hdr_size    = sizeof( struct tcphdr );
      uint16_t* tcp_hdr_16bit = (uint16_t*)&_tcp_hdr;
      for ( int i=0; i < ( tcp_hdr_size >> 2 ); ++i ) {
         checksum += *( tcp_hdr_16bit + i );
      }
      // In case there is a carry over
      while ( checksum >> 16 ) {
         checksum = (uint16_t)checksum + (checksum >> 16);
      }

      _tcp_hdr.check = (uint16_t)(~checksum);
   }

   uint16_t tcp_checksum() { return _tcp_hdr.check; }

   const struct tcphdr& tcp_hdr() { return _tcp_hdr; }
   const struct iphdr& ip_hdr() { return _ip_hdr; }
   
   const char* buffer() {
      memcpy( _buffer, &_ip_hdr, sizeof( struct iphdr ) );
      memcpy( _buffer + sizeof( struct iphdr ), 
              &_tcp_hdr, sizeof( struct tcphdr ) );
      return _buffer;
   }

   ssize_t size() { return sizeof( struct tcphdr) + sizeof( struct iphdr ); }
};

void setup_packet( const struct sockaddr_in*, IP_packet& );
void parse_packet( const char*, ssize_t, const ScanRequest&, IP_packet& );

#endif // parket_h