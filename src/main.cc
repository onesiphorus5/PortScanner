#include "cmdline_parser.h"
#include "scanner.h"
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h> // IPPROTO_TCP
#include <arpa/inet.h>  // inet_addr

#include <unordered_map>

struct sockaddr_in localhost_addr;

const struct sockaddr_in make_addr( const ScanRequest& );
const struct sockaddr_in get_localhost_addr();

int main( int argc, const char* argv[] ) {
   // Seed random number generator
   srand( time( nullptr ) );

   // Set localhost_addr
   localhost_addr = get_localhost_addr();

   CmdLineOptions options = cmdline_parse( argc, argv );
   
   // Create TCP raw sockets
   int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
   if ( skt < 0 ) {
      perror( "socket()" );
      exit( EXIT_FAILURE );
   }

   std::unordered_map<std::string, struct sockaddr_in> addresses; // TCP-IP

   std::vector<ScanRequest> open_ports;
   for ( const ScanRequest& request : options.scan_requests() ) {
      std::string host_port = request.host() + "-" + request.port();
      if ( !addresses.contains( host_port ) ) {
         addresses[host_port] = make_addr( request );
      }
      const struct sockaddr_in target_addr = addresses[host_port];

      // Send IP packet with SYN set 
      bool SYN_sent = send_SYN( skt, &target_addr, request );
      if ( SYN_sent == false ) {
         continue;
      }

      // Receive ACKnowledgement back
      if ( recv_ACK( skt, request ) == true ) {
         open_ports.emplace_back( request );
      }
   }

   // Print open ports
   for ( const auto& request : open_ports ) {
      std::cout << "Port: " << request.port() 
                << " on host: " << request.host() << " is open" << std::endl;
   }

   return 0;
}

const struct sockaddr_in make_addr( const ScanRequest& scan_request ) {
   struct sockaddr_in addr;
   addr.sin_addr.s_addr = inet_addr( scan_request.host().c_str() );
   addr.sin_port = *(uint16_t*)scan_request.port().c_str();

   return addr;
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

   // TODO: send packets

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