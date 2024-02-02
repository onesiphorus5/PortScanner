#include "cmdline_parser.h"

const uint16_t MAX_PORT_COUNT = (1 << 16) - 1;

// TODO: extend it later
CmdLineOptions cmdline_parse( int argc, const char* argv[] ) {
   if ( argc < 3 ) {
      std::cout << "Expecting at least 2 cmd line arguments" << std::endl;
      exit( EXIT_FAILURE );
   }

   CmdLineOptions options;
   std::string host;
   std::string port;
   std::string timeout;
   std::string parallel;

   std::vector<std::string_view> args( argv + 1, argv + argc );
   for ( auto arg : args ) {
      if ( arg.starts_with( "--host" ) ) {
         host = arg.substr( strlen( "--host" ) + 1, arg.size() );
      }
      else if ( arg.starts_with( "--port" ) ) {
         port = arg.substr( strlen( "--port" ) + 1, arg.size() );
      }
      else if ( arg.starts_with( "--timeout" ) ) {
         std::string_view timeout = \
                        arg.substr( strlen( "--timeout" ) + 1, arg.size() );
         options.timeoutIs( std::stoi( timeout.data() ) );
      }
      else if ( arg.starts_with( "--parallel" ) ) {
         std::string_view parallel = \
                        arg.substr( strlen( "--parallel" ) + 1, arg.size() );
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

   // Parse the port option
   std::pair<uint16_t, uint16_t> port_range;
   if ( port.empty() ) {
      port_range.first = 1;
      port_range.second = MAX_PORT_COUNT;
   } else {
      std::string port_start = port.substr( 0, port.find( "-" ) );
      std::string port_last = port.substr( port_start.size() + 1, port.size() );

      port_range.first  = std::stoi( port_start );
      port_range.second = std::stoi( port_last );
   }
   options.port_rangeIs( port_range );

   return options;
}