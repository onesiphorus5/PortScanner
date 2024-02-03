#ifndef cmdline_parser_h
#define cmdline_parser_h

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <iostream>
#include <vector>
#include <unordered_set>
#include <string_view>
#include <utility>

extern const uint16_t MAX_PORT_COUNT;

class CmdLineOptions {
private:
   int _timeout = 5;  // default value: 5 seconds
   // The number of outstanding port scans per thread
   uint16_t _parallel = 8;
   std::unordered_set<uint32_t> _hosts;
   std::pair<uint16_t, uint16_t> _port_range; // closed range
   
public:
   void timeoutIs( int t ) { _timeout = t; }
   int timeout() { return _timeout; }

   void parallelIs( uint16_t p ) {
      // Max allowed outstanding port scans per thread is capped at 16
      if ( p > 16 ) {
         p = 16;
      }
      _parallel = p; 
   }
   uint16_t parallel() { return _parallel; }

   void add_host( uint32_t addr ) {
      _hosts.insert( addr );
   }
   const std::unordered_set<uint32_t>& hosts() const { 
      return _hosts; 
   }

   void port_rangeIs( const std::pair<uint16_t, uint16_t>& range ) {
      _port_range = range;
   }
   const std::pair<uint16_t, uint16_t>& port_range() const { 
      return _port_range;
   }
};

CmdLineOptions cmdline_parse( int argc, const char* argv[] );

#endif // cmdline_parser_h