#include "scanner.h"
#include "packet.h"

const uint32_t BUFF_SIZE = 1 << 16; // 64k bytes

bool send_SYN( int client_skt, 
               const struct sockaddr* target, 
               const ScanRequest& scan_request ) {
   // Setup IP packet
   IP_packet SYN_packet;
   if ( setup_packet( scan_request, SYN_packet ) != 0 ) {
      return false;
   }

   // Send the IP packet to the target
   if ( sendto( client_skt, SYN_packet.to_cstr(), SYN_packet.size(), 0, 
                target, sizeof( struct sockaddr ) ) < 0 ) {
      return false;
   }
   return true;
}


bool recv_ACK( int client_skt, const ScanRequest& scan_request ) {
   struct sockaddr sender_addr;
   socklen_t addrlen = sizeof( struct sockaddr );
   PacketBuffer buffer{BUFF_SIZE};
   if ( recvfrom( client_skt, buffer.ptr(), buffer.size(), 0, 
                  &sender_addr, &addrlen ) < 0 ) {
      return false;
   }

   IP_packet ACK_packet;
   if ( parse_packet( buffer, scan_request, ACK_packet ) != 0 ) {
      return false;
   }
   return true;
}