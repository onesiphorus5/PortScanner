#include "connection.h"

int connect_to_host( const std::string& host, const std::string& port ) {
   int domain   = AF_INET;
   int type     = SOCK_STREAM;
   int protocol = 0;
   struct addrinfo* server_addrinfo;

   int client_socket = 0;

   // Use getaddrinfo() to construct sockaddr_in 
   struct addrinfo hints;
   memset( &hints, 0, sizeof( hints ) );

   hints.ai_family = domain;
   hints.ai_socktype = type;
   hints.ai_protocol = protocol;

   if ( getaddrinfo( host.c_str(), port.c_str(), 
                     &hints, &server_addrinfo ) != 0 ) {
      perror( "getaddrinfo()" );
   }

   // Iterate through server_addrinfo list and use the first valid addr
   struct addrinfo* it = server_addrinfo;

   for ( ; it != NULL; it = it->ai_next ) {
      // Create a socket
      client_socket = socket( it->ai_family, it->ai_socktype, it->ai_protocol );
      if ( client_socket < 0 ) {
         perror( "socket()" );
         continue;
      }
      // Connect to the server
      if ( connect( client_socket, it->ai_addr, it->ai_addrlen ) < 0 ) {
         perror( "connect()" );
         close( client_socket );
         continue;
      }
      break;
   }

   if ( it == NULL ) {
      fprintf( stderr, "Can not connect to the server.\n" );
      client_socket = 0;
   }

   freeaddrinfo( server_addrinfo );

   return client_socket;
}

void setup_local_server( const std::string& port ) {
   // int ret;
   int domain   = AF_INET;
   int type     = SOCK_STREAM;
   int protocol = 0;

   std::string server_ip  = "127.0.0.1";

   struct addrinfo* server_addrinfo;
   int server_socket;
   int backlog = 10;

   // Use getaddrinfo() to construct sockaddr_in 
   struct addrinfo hints;
   memset( &hints, 0, sizeof( hints ) );
   hints.ai_family = domain;
   hints.ai_socktype = type;
   hints.ai_protocol = protocol;

   if ( getaddrinfo( server_ip.c_str(), port.c_str(), 
                     &hints, &server_addrinfo ) != 0 ) {
      perror( "getaddrinfo()" );
   }
   
   struct addrinfo* it = server_addrinfo;
   for ( ; it != NULL; it = it->ai_next ) {  
      // Create a socket
      server_socket = socket( it->ai_family, it->ai_socktype, it->ai_protocol );
      if ( server_socket < 0 ) {
         perror( "socket()" );
         continue;
      }
      
      // Bind the server socket to the server addr and port
      int reuseaddr = 1;
      if ( setsockopt( server_socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, 
                        sizeof( reuseaddr ) ) < 0 ) {
         perror( "setsockopt()" );
         exit( EXIT_FAILURE );
      }
      if ( bind( server_socket, it->ai_addr, it->ai_addrlen ) < 0 ) {
         perror( "bind()" );
         continue;
      }
      break;
   }
   if ( it == NULL ) {
      fprintf( stderr, "Invalid server address.\n" );
      exit( EXIT_FAILURE );
   }

   // Mark the server socket as the listening side
   if ( listen( server_socket, backlog ) < 0 ) {
      perror( "listen()" );
      exit( EXIT_FAILURE );
   }

   // Wait for incoming connections from clients
   int new_socket;
   struct sockaddr_in client_saddr;
   socklen_t addrlen = sizeof( struct sockaddr_in );
   memset( &client_saddr, 0, addrlen );
   char* buffer = (char*) malloc( 1024 );
   while ( 1 ) {
      new_socket = accept( server_socket, 
                           ( struct sockaddr* ) &client_saddr, &addrlen );
      // Read request message from client
      memset( buffer, 0, 1024 );
      int read_cnt = recv( new_socket, buffer, 1024, 0 );
      // buffer[ read_cnt ] = '\0';
      printf( "%s\n", buffer );
      
      // Send client a reply
      memset( buffer, 0, 1024 );
      sprintf( buffer, "Hello client, your port number is %d", 
               client_saddr.sin_port );
      int sent_count = send( new_socket, buffer, strlen( buffer )+1, 0 );
      close( new_socket );
   }  

   // Free resources
   close( server_socket );
   free( buffer );
   freeaddrinfo( server_addrinfo );
}