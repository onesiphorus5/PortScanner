#ifndef cmdline_parser_h
#define cmdline_parser_h

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <unordered_set>
#include <string_view>

class ScanRequest {
private:
   uint64_t _addr_port;
public:
   ScanRequest( uint64_t addr_port ) : _addr_port{ addr_port } {}

   uint64_t addr_port() const { return _addr_port; }

   uint32_t addr() const {
      uint32_t _addr = (uint32_t) ( _addr_port >> 16 ) ;
      return _addr; 
   }

   uint16_t port() const { 
      uint16_t _port = (uint16_t) _addr_port;
      return _port;
   }
};

class CmdLineOptions {
private:
   int _timeout = 5;  // default value: 5 seconds
   uint16_t _parallel = 2; // default value: scan 2 ports at a time
   std::unordered_set<uint32_t> _hosts;
   
public:
   void timeoutIs( int t ) { _timeout = t; }
   int timeout() { return _timeout; }

   void parallelIs( uint16_t p ) { _parallel = p; }
   int parallel() { return _parallel; }

   void add_host( uint32_t addr ) {
      _hosts.insert( addr );
   }
   const std::unordered_set<uint32_t>& hosts() const { 
      return _hosts; 
   }

};

CmdLineOptions cmdline_parse( int argc, const char* argv[] );

#endif // cmdline_parser_h