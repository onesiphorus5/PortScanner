#include "scanner.h"
#include "packet.h"

const uint32_t BUFF_SIZE = 128; // Enough to fit both TCP and IP headers

bool send_SYN( int client_skt, const struct sockaddr_in* target ) {
   // Setup IP packet
   IP_packet SYN_packet;
   setup_packet( target, SYN_packet );

   // Send the IP packet to the target
   if ( sendto( client_skt, SYN_packet.buffer(), SYN_packet.size(), 0, 
                (const struct sockaddr*)target, sizeof( struct sockaddr ) ) < 0 ) {
      perror( "sendto()" );
      return false;
   }
   return true;
}

/*
bool recv_ACK( int client_skt, const struct sockaddr_in* target ) {
   struct sockaddr saddr;
   socklen_t addr_len;

   // Receive IP packets
   char buffer[BUFF_SIZE];
   ssize_t recvd_bytes;
   for ( ; ; ) {
   recvd_bytes = recvfrom( client_skt, buffer, BUFF_SIZE, 0, &saddr, &addr_len );
   if ( recvd_bytes < 0 ) {
      std::cout << "recvfrom() failed!" << std::endl;
      return false;
   }
   }

   // Parse the received IP packet
   IP_packet ACK_packet;
   parse_packet( buffer, recvd_bytes, scan_request, ACK_packet );

   return true;
}
*/