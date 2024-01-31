#include "cmdline_parser.h"
#include "scanner.h"
#include <time.h>
#include <stdlib.h>
#include <stop_token>
#include <chrono>

const uint16_t MAX_PORT_COUNT = (1 << 16 ) - 1;

struct sockaddr_in localhost_addr;

std::unordered_set<uint32_t> pending_requests;
std::unordered_map<uint32_t, std::unordered_set<uint16_t>> open_ports;
std::mutex open_ports_mutex;

// helper function
uint64_t addr_port( uint32_t, uint16_t );

int main( int argc, const char* argv[] ) {
   // Seed random number generator
   srand( time( nullptr ) );

   // Parse command line arguments
   CmdLineOptions options = cmdline_parse( argc, argv );
   pending_requests = options.hosts();

   uint16_t batch_size = 1 << 12;

   // Set localhost_addr
   localhost_addr = get_localhost_addr();

   // Spawn a thread that will snoop incoming IP packets
   // looking for the ACKnowledgement packet
   std::vector<std::jthread> snooping_threads;
   for ( int i=0; i<options.parallel(); ++i ) {
      snooping_threads.emplace_back( snoop_network );
   }

   // Send SYN packets
   // TODO: send SYN packets in parallel
   for ( uint32_t host : options.hosts() ) {
      std::vector<std::jthread> sending_threads;
      for ( int i=1; i < MAX_PORT_COUNT; i += batch_size ) {
         sending_threads.emplace_back( send_SYN_packets, host, i, batch_size );
      }

      for ( auto& th : sending_threads ) {
         th.join();
      }
   }

   // Give the snooping threads more time to read the replies
   auto timeout = std::chrono::milliseconds( options.timeout() * 1000 );
   std::this_thread::sleep_for( timeout ); 

   for ( auto& thd : snooping_threads ) {
      thd.request_stop();
      thd.join();
   }

   // Print open ports
   struct in_addr saddr;
   for ( const auto&[ _addr, _ports] : open_ports ) {
      for ( uint16_t _port : _ports ) {
         saddr.s_addr = _addr;
         std::cout << " Port: " << ntohs( _port ) << " on host: " 
                   << inet_ntoa( saddr ) << " is OPEN" << std::endl;
      }
   }

   return 0;
}