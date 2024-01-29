#ifndef cmdline_parser_h
#define cmdline_parser_h

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>

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
   std::vector<ScanRequest> _scan_requests;
   
public:
   const std::vector<ScanRequest>& scan_requests() const { return _scan_requests; }

   void add_request( uint64_t addr_port ) {
      _scan_requests.emplace_back( addr_port );
   }
};

CmdLineOptions cmdline_parse( int argc, const char* argv[] );

#endif // cmdline_parser_h