#include "scanner.h"
#include "packet.h"

const uint32_t BUFF_SIZE = 128; // Enough to fit both TCP and IP headers

bool send_SYN( int client_skt, const struct sockaddr_in* target ) {
   // Setup IP packet
   IP_packet SYN_packet;
   SYN_packet.setup_packet( target );

   // Send the IP packet to the target
   if ( sendto( client_skt, SYN_packet.buffer(), SYN_packet.size(), 0, 
                (const struct sockaddr*)target, sizeof( struct sockaddr ) ) < 0 ) {
      perror( "sendto()" );
      return false;
   }
   return true;
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

      // Check if it's one of the packets we are expecting.
      pending_requests_mutex.lock();
      if ( pending_requests.count( addr_port ) && 
           ( tcp_header->syn == 1 ) && 
           ( tcp_header->ack == 1 ) ) {
         open_ports_mutex.lock();
         open_ports[ addr_port ] = true;
         open_ports_mutex.unlock();
      }
      pending_requests_mutex.unlock();

      // If we've received all the packets we were expecting, end the loop.
      open_ports_mutex.lock();
      if ( open_ports.size() == pending_requests.size() ) {
         open_ports_mutex.unlock();
         break;
      }
      open_ports_mutex.unlock();
   }

   close( raw_skt );
}