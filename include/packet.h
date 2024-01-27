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

// class PacketBuffer{
// private:
//    char* _ptr;
//    ssize_t _size;
// 
// public:
//    PacketBuffer( ssize_t size ) : _size{size} {
//       _ptr = new char[size];
//    }
//    ~PacketBuffer() { delete[] _ptr; }
// 
//    char* ptr() { return _ptr; }
//    ssize_t size() { return _size; }
// };

class IP_packet{
private:
   // Useful for checksum computation
   struct TCP_pseudoHdr{
      uint32_t src_addr;
      uint32_t dst_addr;
      uint8_t  zero;
      uint8_t  ptcl; // protocol
      uint16_t tcp_len;
      tcphdr tcp_header;

      ssize_t size() {
         return sizeof( src_addr ) + sizeof( dst_addr ) +
                sizeof( zero ) + sizeof( ptcl ) + sizeof( tcp_len ) +
                sizeof ( tcp_header );
      }
   };

   struct tcphdr _tcp_hdr;
   struct iphdr  _ip_hdr;
   char* _buffer;

   // helper function
   uint16_t compute_checksum( const char* header, ssize_t hdr_size ) {
      uint32_t sum = 0;
      ssize_t hdr_size_16bit = hdr_size/2;
      uint16_t* header_16bit = (uint16_t*)header;
      for ( int i=0; i < hdr_size_16bit; ++i ) {
         sum += *( header_16bit + i );
         // Check if there is a carry over bit
         if ( sum >> 16 ) {
            sum = sum << 16;
            sum = sum >> 16;
            sum += 1;
         }
      }
   
      uint16_t checksum = (uint16_t) sum;
      checksum = ~checksum;
      return checksum;
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
      TCP_pseudoHdr tcp_pseudoHeader;

      tcp_pseudoHeader.src_addr = _ip_hdr.saddr;
      tcp_pseudoHeader.dst_addr = _ip_hdr.daddr;
      tcp_pseudoHeader.zero = 0;
      tcp_pseudoHeader.ptcl = IPPROTO_TCP;
      tcp_pseudoHeader.tcp_len = sizeof( struct tcphdr );
      tcp_pseudoHeader.tcp_header = _tcp_hdr;

      ssize_t header_size = sizeof( tcp_pseudoHeader );
      // Adding padding if necessary
      if ( header_size % 2 == 1 ) {
         header_size += 1;
      }
      char buffer[header_size];
      memset( buffer, 0, header_size );
      memcpy( buffer, &tcp_pseudoHeader, tcp_pseudoHeader.size() );

      _tcp_hdr.check = compute_checksum( (const char*)buffer, header_size );
   }

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