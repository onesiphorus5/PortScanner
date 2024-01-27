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

struct sockaddr_in localhost_addr;

const struct sockaddr_in make_addr( const ScanRequest& );
const struct sockaddr_in get_localhost_addr();

/* Related to the snooping thread*/
std::unordered_map<uint64_t, bool> open_ports;
std::mutex open_ports_mutex;
std::unordered_map<uint64_t, bool> scan_requests; // addr + port
std::mutex scan_requests_mutex;
void snoop_network();

int main( int argc, const char* argv[] ) {
   // Seed random number generator
   srand( time( nullptr ) );

   // Spawn a thread that will snoop incoming IP packets
   // looking for the ACKnowledgement packet
   std::jthread snoop_thread( snoop_network );

   // Set localhost_addr
   localhost_addr = get_localhost_addr();

   CmdLineOptions options = cmdline_parse( argc, argv );
   
   // Create TCP raw sockets
   int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   for ( const ScanRequest& request : options.scan_requests() ) {
      scan_requests_mutex.lock();
      scan_requests[ request.addr_port() ] = true;
      scan_requests_mutex.unlock();
 
      // Send IP packet with SYN set
      struct sockaddr_in target_addr;
      target_addr.sin_family = AF_INET;
      target_addr.sin_addr = request.addr;
      target_addr.sin_port = request.port;

      bool SYN_sent = send_SYN( skt, &target_addr );
      if ( SYN_sent == false ) {
         continue;
      }
   }

   // Sleep for about 5 seconds

   // Print open ports
   // for ( const auto& request : open_ports ) {
   //    std::cout << "Port: " << request.port() 
   //              << " on host: " << request.host() << " is open" << std::endl;
   // }

   return 0;
}

const struct sockaddr_in get_localhost_addr() {
   struct sockaddr_in local_addr;

   const ssize_t BUFFSIZE = 32; // Enough to give us IP header
   char buffer[ BUFFSIZE ];

   int raw_skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( raw_skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   // We need to sniff any IP packet, so ping replies are enough.
   if ( fork() == 0 ) {
      close( 1 ); // close stdout 
      close( 2 ); // close stderr
      execlp( "ping", "ping", "-c", "10", "-4", "google.com", (char*) nullptr );
   }

   struct sockaddr saddr;
   socklen_t saddr_len;
   for ( ; ; ) {
      if ( recvfrom( raw_skt, buffer, BUFFSIZE, 0, &saddr, &saddr_len ) < 0 ) {
         continue;
      }
      local_addr.sin_addr.s_addr = ((iphdr*)buffer)->daddr;
      break;
   }

   return local_addr;
}

void snoop_network() {
   int raw_skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( raw_skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   ssize_t recvd_bytes;
   ssize_t buffersize = 128; // Enough to fit both the IP && TCP header
   char buffer[ buffersize ];

   struct sockaddr src_addr;
   socklen_t addrlen = sizeof( struct sockaddr );

   struct iphdr* ip_header;
   struct tcphdr* tcp_header;
   uint32_t target_addr;
   uint16_t target_port;
   uint64_t addr_port;
   for ( ; ; ) {
      memset( buffer, 0, buffersize );
      if ( recvfrom( raw_skt, buffer, buffersize, 0, &src_addr, &addrlen ) < 0 ) {
         perror( "recvfrom()" );
         exit( EXIT_FAILURE );
      }

      ip_header = (struct iphdr*)buffer;
      tcp_header = (struct tcphdr*)( buffer + sizeof( struct iphdr ) );

      target_addr = ntohl( ip_header->saddr );
      target_port = ntohs( tcp_header->source );

      addr_port = target_addr;
      addr_port = addr_port << 32;
      addr_port = addr_port | target_port;      

      scan_requests_mutex.lock();
      if ( scan_requests.count( addr_port ) ) {
         open_ports_mutex.lock();
         open_ports[ addr_port ] = true;
         open_ports_mutex.unlock();
      }

      open_ports_mutex.lock();
      if ( open_ports.size() == scan_requests.size() ) {
         open_ports_mutex.unlock();
         scan_requests_mutex.unlock();     
         break;
      }
      open_ports_mutex.unlock();
      scan_requests_mutex.unlock();
   }
}