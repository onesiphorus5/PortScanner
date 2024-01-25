#include "cmdline_parser.h"
#include "scanner.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h> // IPPROTO_TCP

#include <unordered_map>

struct sockaddr make_addr( const ScanRequest& scan_request ) {
   struct sockaddr addr;

   return addr;
}

int main( int argc, const char* argv[] ) {
   CmdLineOptions options = cmdline_parse( argc, argv );
   
   // Create TCP raw sockets
   int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   std::unordered_map<std::string, sockaddr> addresses; // TCP-IP

   std::vector<ScanRequest> open_ports{};
   for ( const ScanRequest& request : options.scan_requests() ) {
      std::string host_port = request.host() + "-" + request.port();
      if ( !addresses.contains( host_port ) ) {
         addresses[host_port] = make_addr( request );
      }
      const struct sockaddr addr = addresses[host_port];
      // if ( addresses.count( request.host() + request.port() ))
      bool SYN_sent = send_SYN( skt, &addr, request );
      if ( SYN_sent == false ) {
         continue;
      }
      if ( recv_ACK( skt, request ) == true ) {
         open_ports.emplace_back( request );
      }
   }

   for ( const auto& request : open_ports ) {
      std::cout << "Port: " << request.port() 
                << " on host: " << request.host() << " is open" << std::endl;
   }

   return 0;
}