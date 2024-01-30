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
   struct TCP_pseudo_hdr {
      uint32_t src;
      uint32_t dst;
      uint8_t zero;
      uint8_t protocol;
      uint16_t len;

      ssize_t size() { 
         return sizeof( src ) + sizeof( dst ) + sizeof( zero ) +
                sizeof( protocol ) + sizeof( len );
      }
   };

   struct tcphdr* _tcp_hdr;
   struct iphdr*  _ip_hdr;
   char* _buffer;

   // helper function
   uint16_t cksum16( const uint16_t*, ssize_t, uint32_t ) const;
  
public:
   IP_packet() { 
      _buffer = new char[size()]; 
      memset( _buffer, 0, size() );   
   }
   ~IP_packet() { delete[] _buffer; }

   void tcp_hdrIs( struct tcphdr* hdr ) { _tcp_hdr = hdr; }
   void ip_hdrIs( struct iphdr* hdr ) { _ip_hdr = hdr; }

   // void set_ipHeaderChecksum() { _ip_hdr.check = htons ( compute_checksum_ip() ); }
   // void set_tcpHeaderChecksum() { _tcp_hdr.check = htons( compute_checksum_tcp() ); }

   const struct tcphdr* tcp_hdr() { return _tcp_hdr; }
   const struct iphdr* ip_hdr() { return _ip_hdr; }

   uint16_t cksum_tcp() const;
   
   const char* buffer() const { return _buffer; }
   ssize_t size() { return sizeof( struct tcphdr) + sizeof( struct iphdr ); }
   void setup_packet( const struct sockaddr_in* );
};

#endif // parket_h