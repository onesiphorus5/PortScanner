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