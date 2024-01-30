#include "cmdline_parser.h"
#include "scanner.h"
#include <time.h>
#include <stdlib.h>
#include <stop_token>
#include <chrono>

struct sockaddr_in localhost_addr;

std::unordered_map<uint64_t, bool> open_ports;
std::mutex open_ports_mutex;
std::unordered_map<uint64_t, bool> pending_requests; // addr + port
std::mutex pending_requests_mutex;

int main( int argc, const char* argv[] ) {
   // Seed random number generator
   srand( time( nullptr ) );

   // Set localhost_addr
   localhost_addr = get_localhost_addr();

   // Spawn a thread that will snoop incoming IP packets
   // looking for the ACKnowledgement packet
   std::jthread snooping_thread( snoop_network );

   CmdLineOptions options = cmdline_parse( argc, argv );
   
   // Create TCP raw sockets
   int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }
   // Set the IP_HDRINCL option so we can write our own IP header
   int on = 1;
   setsockopt(skt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

   for ( const ScanRequest& request : options.scan_requests() ) {
      // Send IP packet with SYN set
      struct sockaddr_in target_addr;
      target_addr.sin_family = AF_INET;
      target_addr.sin_addr.s_addr = request.addr();
      target_addr.sin_port = request.port();

      bool SYN_sent = send_SYN( skt, &target_addr );
      if ( SYN_sent == false ) {
         continue;
      }
      pending_requests_mutex.lock();
      pending_requests[ request.addr_port() ] = true;
      pending_requests_mutex.unlock();
   }
   close( skt );

   int timeout = 5000; // 5 secs
   std::this_thread::sleep_for( std::chrono::milliseconds( timeout ) );

   // Print open ports
   pending_requests_mutex.lock();
   open_ports_mutex.lock();
   struct in_addr snooped_addr;
   uint16_t snooped_port;
   for ( const auto& [ key, _] : pending_requests ) {
      if ( open_ports.contains( key ) ) {
         uint64_t addr_port = key;
         snooped_port = (uint16_t) addr_port;
         addr_port = addr_port >> 16;
         snooped_addr.s_addr = (uint32_t) addr_port;
   
         std::cout << " Port: " << ntohs( snooped_port ) << " on host: "
                   << inet_ntoa( snooped_addr ) << " is OPEN" << std::endl;
      } else {
         std::cout << " Port: " << ntohs( snooped_port ) << " on host: "
                   << inet_ntoa( snooped_addr ) << " is NOT OPEN" << std::endl;

      }
   }
   open_ports_mutex.unlock();
   pending_requests_mutex.unlock();

   // Stop the snooping thread
   snooping_thread.request_stop();
   snooping_thread.join();

   return 0;
}