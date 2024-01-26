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

class PacketBuffer{
private:
   char* _ptr;
   ssize_t _size;

public:
   PacketBuffer( ssize_t size ) : _size{size} {
      _ptr = new char[size];
   }
   ~PacketBuffer() { delete[] _ptr; }

   char* ptr() { return _ptr; }
   ssize_t size() { return _size; }
};

class IP_packet{
private:
   struct tcphdr _tcp_hdr;
   struct iphdr  _ip_hdr;

   char* _buffer;

public:
   IP_packet() { _buffer = new char[size()]; }
   ~IP_packet() { delete[] _buffer; }

   void tcp_hdrIs( const struct tcphdr& hdr ) { 
      _tcp_hdr = hdr;
      memcpy( _buffer + sizeof( struct iphdr ), 
              &_tcp_hdr, sizeof( struct tcphdr ) );
   }
   void ip_hdrIs( const struct iphdr& hdr ) { 
      _ip_hdr = hdr;
      memcpy( _buffer, &_ip_hdr, sizeof( struct iphdr ) );
   }

   const struct tcphdr& tcp_hdr() { return _tcp_hdr; }
   const struct iphdr& ip_hdr() { return _ip_hdr; }

   ssize_t size() { return sizeof( struct tcphdr) + sizeof( struct iphdr ); }
   
   const char* buffer() const { return _buffer; }
};

void setup_packet( const struct sockaddr_in*, IP_packet& );
void parse_packet( const char*, ssize_t, const ScanRequest&, IP_packet& );

#endif // parket_h