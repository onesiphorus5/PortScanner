#include "cmdline_parser.h"

// TODO: extend it later
CmdLineOptions cmdline_parse( int argc, const char* argv[] ) {
   if ( argc < 3 ) {
      std::cout << "Expecting at least 2 cmd line arguments" << std::endl;
      exit( EXIT_FAILURE );
   }

   CmdLineOptions options;
   std::string host;
   std::string timeout;
   std::string parallel;

   std::vector<std::string_view> args( argv + 1, argv + argc );
   for ( auto arg : args ) {
      if ( arg.starts_with( "--host" ) ) {
         host = arg.substr( sizeof( "--host" ), arg.size() );
      }
      else if ( arg.starts_with( "--timeout" ) ) {
         std::string_view timeout = arg.substr( sizeof( "--timeout" ), arg.size() );
         options.timeoutIs( std::stoi( timeout.data() ) );
      }
      else if ( arg.starts_with( "--parallel" ) ) {
         std::string_view parallel = arg.substr( sizeof( "--parallel" ), arg.size() );
         options.parallelIs( std::stoi( parallel.data() ) );
         // At max 8 ports should be scanned in parallel
         if ( options.parallel() > 8 ) {
            options.parallelIs( 8 );
         }
      }
      else {
         std::cout << "Option " << arg << " not supported" << std::endl;
         exit( EXIT_FAILURE );
      }    
   }
   // TODO: host needs to be parsed further
   if ( host == "localhost" ) {
      host = "127.0.0.1";
   }
   options.add_host( inet_addr( host.c_str() ) );

   // exit( EXIT_FAILURE );

   return options;
}