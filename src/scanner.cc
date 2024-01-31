#include "scanner.h"
#include "packet.h"

// #include <sys/socket.h>
// #include <netinet/in.h>
#include <arpa/inet.h>

const uint32_t BUFF_SIZE = 128; // Enough to fit both TCP and IP headers
const uint16_t SOCKET_COUNT = 16; 

void send_SYN_packets( uint32_t target_addr, uint16_t start_port,
                       uint16_t batchsize ) {
   std::vector<int> raw_skts;
   int on = 1;
   for ( int i=0; i < SOCKET_COUNT; ++i ) {
      int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
      if ( skt < 0 ) {
         perror( "socket()" );
         exit( EXIT_FAILURE ); 
      }
      // Set the IP_HDRINCL option so we can write our own IP header
      setsockopt(skt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
      raw_skts.push_back( skt );
   }

   struct sockaddr_in target;
   target.sin_family = AF_INET;
   target.sin_addr.s_addr = target_addr;

   for ( int port = start_port; ( port < start_port + batchsize ) &&
                                     ( port <= MAX_PORT_COUNT ); ++port ) {
      target.sin_port = htons( port );
      
      IP_packet SYN_packet;  // TODO: implement a clear function
      SYN_packet.setup_packet( &target );

      int skt = raw_skts[ port % SOCKET_COUNT ];
      if ( sendto( skt, SYN_packet.buffer(), SYN_packet.size(), 0, 
                   (const struct sockaddr*)&target, sizeof( struct sockaddr ) ) < 0 ) {
         perror( "sendto()" );
         exit( EXIT_FAILURE );
      }
   }
   for ( int skt : raw_skts ) {
      close( skt );
   } 
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
   while ( !stopToken.stop_requested() ) {
      memset( buffer, 0, buffersize );
      if ( recvfrom( raw_skt, buffer, buffersize, 0, &src_addr, &addrlen ) < 0 ) {
         perror( "recvfrom()" );
         exit( EXIT_FAILURE );
      }

      ip_header = (struct iphdr*)buffer;
      tcp_header = (struct tcphdr*)( buffer + sizeof( struct iphdr ) );

      // Check if it's one of the packets we are expecting.
      if ( pending_requests.contains( ip_header->saddr ) && 
           ( tcp_header->syn == 1 ) && 
           ( tcp_header->ack == 1 ) ) {
         open_ports_mutex.lock();
         open_ports[ ip_header->saddr ].insert( tcp_header->source );
         open_ports_mutex.unlock();
      }
   }

   close( raw_skt );
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