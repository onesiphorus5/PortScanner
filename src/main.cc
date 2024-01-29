#include "cmdline_parser.h"
#include "scanner.h"
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h> // IPPROTO_TCP
#include <netinet/tcp.h> // IPPROTO_TCP
#include <arpa/inet.h>  // inet_addr
#include <unistd.h>
#include <string.h>

#include <unordered_map>
#include <thread>
#include <mutex>
#include <stop_token>
#include <chrono>

struct sockaddr_in localhost_addr;

const struct sockaddr_in make_addr( const ScanRequest& );
const struct sockaddr_in get_localhost_addr();

/* Related to the snooping thread*/
std::unordered_map<uint64_t, bool> open_ports;
std::mutex open_ports_mutex;
std::unordered_map<uint64_t, bool> pending_requests; // addr + port
std::mutex pending_requests_mutex;
void snoop_network( std::stop_token );

int main( int argc, const char* argv[] ) {
   // Seed random number generator
   srand( time( nullptr ) );

   // Set localhost_addr
   std::cout << "[before] get_localhost_addr()" << std::endl;
   localhost_addr = get_localhost_addr();
   std::cout << "[after] get_localhost_addr()" << std::endl;

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
   // setsockopt(skt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

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

   int timeout = 50000; // 50 secs
   std::this_thread::sleep_for( std::chrono::milliseconds( timeout ) );

   // Print open ports
   open_ports_mutex.lock();
   struct in_addr snooped_addr;
   uint16_t snooped_port;
   for ( const auto& [ key, _] : open_ports ) {
      uint64_t addr_port = key;
      snooped_port = (uint16_t) addr_port;
      addr_port = addr_port >> 16;
      snooped_addr.s_addr = (uint32_t) addr_port;

      std::cout << " Port: " << snooped_port << " on host: "
                << inet_ntoa( snooped_addr ) << "is open" << std::endl;
   }
   open_ports_mutex.unlock();

   // Stop the snooping thread
   snooping_thread.request_stop();
   snooping_thread.join();

   return 0;
}

const struct sockaddr_in get_localhost_addr() {
   // We need to sniff any IP packet, so ping replies are enough.
   if ( fork() == 0 ) {
      close( 1 ); // close stdout 
      close( 2 ); // close stderr
      execlp( "ping", "ping", "-c", "5", "-4", "dns.google.com", (char*) nullptr );
   }
   struct sockaddr_in local_addr;

   const ssize_t BUFFSIZE = 65535; // Max IP packet size
   char buffer[ BUFFSIZE ];

   int raw_skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( raw_skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   struct sockaddr saddr;
   socklen_t saddr_len = sizeof( struct sockaddr );
   for ( ; ; ) {
      if ( recvfrom( raw_skt, buffer, BUFFSIZE, 0, &saddr, &saddr_len ) < 0 ) {
         continue;
      }
      local_addr.sin_addr.s_addr = ((iphdr*)buffer)->daddr;
      break;
   }
   close( raw_skt );

   return local_addr;
}

void snoop_network( std::stop_token stopToken ) {
   int raw_skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( raw_skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   ssize_t recvd_bytes;
   ssize_t buffersize = 65535; // Max IP packet size
   char buffer[ buffersize ];

   struct sockaddr src_addr;
   socklen_t addrlen = sizeof( struct sockaddr );

   struct iphdr* ip_header;
   struct tcphdr* tcp_header;
   uint32_t target_addr;
   uint16_t target_port;
   uint64_t addr_port;
   while ( !stopToken.stop_requested() ) {
      memset( buffer, 0, buffersize );
      if ( recvfrom( raw_skt, buffer, buffersize, 0, &src_addr, &addrlen ) < 0 ) {
         perror( "recvfrom()" );
         exit( EXIT_FAILURE );
      }

      ip_header = (struct iphdr*)buffer;
      tcp_header = (struct tcphdr*)( buffer + sizeof( struct iphdr ) );

      target_addr = ip_header->saddr;
      target_port = tcp_header->source;

      addr_port = target_addr;
      addr_port = addr_port << 16;
      addr_port = addr_port | target_port;

      // For debugging
      struct in_addr saddr;
      saddr.s_addr = ntohl( target_addr );
      std::cout << "target addr: " << inet_ntoa( saddr ) << std::endl;
      std::cout << "target port: " << ntohs( target_port ) << std::endl;
      // For debugging -- end

      pending_requests_mutex.lock();
      if ( pending_requests.count( addr_port ) ) {
         open_ports_mutex.lock();
         open_ports[ addr_port ] = true;
         open_ports_mutex.unlock();
      }

      open_ports_mutex.lock();
      if ( open_ports.size() == pending_requests.size() ) {
         open_ports_mutex.unlock();
         pending_requests_mutex.unlock();     
         break;
      }
      open_ports_mutex.unlock();
      pending_requests_mutex.unlock();
   }

   close( raw_skt );
}