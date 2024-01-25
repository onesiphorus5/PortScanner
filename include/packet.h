#ifndef parket_h
#define parket_h

#include "cmdline_parser.h"
#include <sys/types.h>
#include <sys/socket.h>

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
   std::string buffer;

public:
   const char* to_cstr() { return buffer.c_str(); }
   ssize_t size() { return buffer.size(); }
};

int setup_packet( const ScanRequest&, IP_packet& );
int parse_packet( const PacketBuffer&, const ScanRequest&, IP_packet& );

#endif // parket_h