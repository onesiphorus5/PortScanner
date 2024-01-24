#include "connection.h"

int main( int argc, const char* argv[] ) {
   if ( argc != 2 ) {
      std::cout << "test_server expect a 'port' argument" << std::endl;
      exit( EXIT_FAILURE );
   }

   // Setup server 
   setup_local_server( argv[1] ); // never returns

   return 0;
}