#include "cmdline_parser.h"

// TODO: extend it later
CmdLineOptions cmdline_parse( int argc, const char* argv[] ) {
   if ( argc < 3 ) {
      std::cout << "Expecting at least 2 cmd line arguments" << std::endl;
      exit( EXIT_FAILURE );
   }
   std::string host = argv[1];
   std::string port = argv[2];
   
   if ( host == "localhost" ) {
      host = "127.0.0.1";
   }

   uint32_t addr = inet_addr( host.c_str() );
   if ( addr == -1 ) {
      std::cout << "Invalid host: " << host << std::endl;
      exit( EXIT_FAILURE );
   }
   uint16_t port_d = (uint16_t) stoi( port ); // port in digit
   port_d = htons( port_d );

   uint64_t addr_port = addr;
   addr_port = addr_port << 32;
   addr_port = addr_port | port_d;

   CmdLineOptions options;
   options.add_request( host, port );

   return options;
}