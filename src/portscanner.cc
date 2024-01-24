#include "connection.h"

int main( int argc, const char* argv[] ) {
   // portscanner expects both the host and port arguments
   std::string host
   std::string port
   if ( argc == 1 ) {
      host = "127.0.0.1"
   }
   if ( argc >= 2 ) {
      if ( argv[1] == "localhost") {
         host = "127.0.0.1"
      } else {
         host = argv[1];
      }
   }
   if ( argc == 3 ) {
      port = argv[2];
   }

   if ( argc == 3 ) {
      std::cout << "Scanning host: " << host << " port: " << port << std::endl;
   } else {
      std::cout << "Scanning host: " << host 
                << " for all open ports" << std::endl;
   }

   int client_skt = connect_to_host( host, port );
   if ( client_skt != 0 ) {
      std::cout << "Port: " << port << " is open" << std::endl;
   }

   return 0;
}