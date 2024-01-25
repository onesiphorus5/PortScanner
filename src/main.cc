#include "cmdline_parser.h"
#include "scanner.h"

int main( int argc, const char* argv[] ) {
   CmdLineOptions options = cmdline_parse( argc, argv );

   // Create TCP raw sockets


   std::vector<ScanRequest> open_ports{};
   for ( const ScanRequest& request : options.scan_requests() ) {
      bool SYN_sent = send_SYN( request );
      if ( SYN_sent == false ) {
         continue;
      }
      if ( recv_ACK( request ) == true ) {
         open_ports.emplace_back( request );
      }
   }

   for ( const auto& request : open_ports ) {
      std::cout << "Port: " << request.port() 
                << " on host: " << request.host() << " is open" << std::endl;
   }

   return 0;
}