#include "cmdline_parser.h"
#include "scanner.h"
#include <time.h>
#include <stdlib.h>
#include <stop_token>
#include <chrono>

struct sockaddr_in localhost_addr;

std::unordered_set<uint32_t> host_requests;
std::unordered_map<uint32_t, std::unordered_set<uint16_t>> host_open_ports;
std::mutex host_open_ports_mutex;

std::list<thread_arguments> thread_args_list;

// SYN packets will be sent by multiple threads.
// Each thread will send at most 2^12 SYN packets. If there are  
// 2^12 (or less) ports to scan, only 1 thread will be used.
const uint16_t BATCH_SIZE = 1 << 12;

// helper function
uint64_t addr_port( uint32_t, uint16_t );

int main( int argc, const char* argv[] ) {
   // Seed random number generator
   srand( time( nullptr ) );

   // Parse command line arguments
   CmdLineOptions options = cmdline_parse( argc, argv );
   host_requests = options.hosts();

   // The number of outstanding port scans
   uint16_t parallel = options.parallel();

   // Set localhost_addr
   localhost_addr = get_localhost_addr();


   uint16_t first_port = options.port_range().first;
   uint16_t last_port  = options.port_range().second;
   for ( uint32_t host : options.hosts() ) {
      std::vector<std::jthread> sending_threads;
      std::vector<std::jthread> recving_threads;

      int sleep_sec = 0;
      for ( int i=first_port; i < last_port; i += BATCH_SIZE ) {
         pthread_mutex_t m;
         pthread_cond_t cv;
         pthread_mutex_t cv_m;
         thread_args_list.emplace_back( host, (uint16_t)i, last_port, 
                                       options.parallel(), options.timeout(), 
                                       m, cv, cv_m );
         auto it_end = thread_args_list.end();
         it_end = --it_end;
         sending_threads.emplace_back( send_SYN_packets, it_end );
         recving_threads.emplace_back( snoop_network, it_end );

         sleep_sec += 5;
      }

      for ( auto& th : sending_threads ) {
         th.join();
      }

      sleep( sleep_sec );
      for ( auto& th : recving_threads ) {
         th.request_stop();
         th.join();
      }
   }

   // Print open ports
   struct in_addr saddr;
   for ( const auto&[ _addr, _ports] : host_open_ports ) {
      for ( uint16_t _port : _ports ) {
         saddr.s_addr = _addr;
         std::cout << " Port: " << ntohs( _port ) << " on host: " 
                   << inet_ntoa( saddr ) << " is OPEN" << std::endl;
      }
      std::cout << std::endl;
   }

   return 0;
}