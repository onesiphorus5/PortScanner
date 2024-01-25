#include "cmdline_parser.h"

// TODO: extend it later
CmdLineOptions cmdline_parse( int argc, const char* argv[] ) {
   if ( argc < 3 ) {
      std::cout << "Expecting at least 2 cmd line arguments" << std::endl;
      exit( EXIT_FAILURE );
   }
   std::string host = argv[1];
   std::string port = argv[2];
   
   CmdLineOptions options;
   options.add_request( host, port );

   return options;
}