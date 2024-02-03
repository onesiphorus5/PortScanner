#include "scanner.h"
#include "packet.h"

// #include <sys/socket.h>
// #include <netinet/in.h>
#include <arpa/inet.h>

const uint32_t BUFF_SIZE = 128; // Enough to fit both TCP and IP headers

void send_SYN_packets( std::list<thread_arguments>::iterator args) {
   // thread_arguments& args->= thread_args_vec[index];

   int epollfd;
   const uint16_t MAX_EVENTS = args->parallel;
   struct epoll_event ev, events[ MAX_EVENTS ];

   if ( ( epollfd = epoll_create1( 0 ) ) == -1 ) {
      perror( "epoll_create1()" );
      exit( EXIT_FAILURE );
   }
   ev.events = EPOLLOUT;
   
   std::vector<int> raw_skts;
   int on = 1;
   for ( int i=0; i < args->parallel; ++i ) {
      int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
      if ( skt < 0 ) {
         perror( "socket()" );
         exit( EXIT_FAILURE ); 
      }
      // Set the socket file descriptor to non-blocking
      int flags = fcntl( skt, F_GETFL, 0 );
      if ( flags == -1 ) {
         perror( "fcntl()" );
         exit( EXIT_FAILURE );
      }
      flags |= O_NONBLOCK;
      if ( fcntl( skt, F_SETFL, flags ) == -1 ) {
         perror( "fcntl()" );
         exit( EXIT_FAILURE );
      }

      // Set the IP_HDRINCL option so we can write our own IP header
      setsockopt(skt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
      raw_skts.push_back( skt );

      // Add the skt to the monitored list
      ev.data.fd = skt;
      if ( epoll_ctl( epollfd, EPOLL_CTL_ADD, skt, &ev ) == -1 ) {
         perror( "epoll_ctl()" );
         exit( EXIT_FAILURE );
      }
   }

   struct sockaddr_in target;
   target.sin_family = AF_INET;
   target.sin_addr.s_addr = args->target_addr;

   int port = args->start_port;
   for (  ; ( port < args->start_port + BATCH_SIZE ) && 
            ( port <= args->last_port ) ; ) {
      // Wait for either of the following conditions to be true:
      // 1. pending_requests_list to be empty, that is receive replies for 
      //    the requests made
      // 2. the timeout to expire
      if ( pthread_mutex_lock( &args->requests_mutex ) != 0 ) {
         perror( "pthread_mutex_lock()" );
         exit( EXIT_FAILURE );
      }
      // args->requests_cv.wait_for( lk, std::chrono::milliseconds( args->timeout ), 
      //                            [&]{ return args->requests_list.empty(); } );
      auto it = args->requests_list.begin();
      while ( it != args->requests_list.end() ) {
         if ( it->second == 2 ) {
            args->requests_map.erase( it->first );
            it = args->requests_list.erase( it );
         } else {
            it++;
         }
      }
      if ( pthread_mutex_unlock( &args->requests_mutex ) != 0 ) {
         perror( "pthread_unlock()" );
         exit( EXIT_FAILURE );
      }

      int fd_count = epoll_wait( epollfd, events, MAX_EVENTS, -1 );
      if ( fd_count == -1 ) {
         perror( "epoll_wait()" );
         exit( EXIT_FAILURE );
      }

      if ( pthread_mutex_lock( &args->requests_mutex ) != 0 ) {
         perror( "pthread_mutex_lock()" );
         exit( EXIT_FAILURE );
      }
      it = args->requests_list.begin();
      int i = 0;
      // Resend SYN packets
      for ( ; i < fd_count; ++i ) {
         if ( it == args->requests_list.end() ) {
            break;
         }
         // Increment the "send count"
         (*it).second += 1;

         // Resend the packets
         int ready_skt = events[i].data.fd;
         target.sin_port = htons( (*it).first );

         IP_packet SYN_packet;  // TODO: implement a clear function
         SYN_packet.setup_packet( &target );

         if ( sendto( ready_skt, SYN_packet.buffer(), SYN_packet.size(), 0, 
                      (const struct sockaddr*)&target, 
                      sizeof( struct sockaddr ) ) < 0 ) {
            perror( "sendto()" );
            exit( EXIT_FAILURE );
         }

         ++it;      
      }

      // Send new packets
      for ( ; ( i < fd_count ) && 
              ( port < args->start_port + BATCH_SIZE ) &&
              ( port <= args->last_port ); ++i ) {
         int ready_skt = events[i].data.fd;
         target.sin_port = htons( port );

         if ( args->requests_list.size() == args->parallel ) {
            break;
         }

         auto node = std::pair<uint16_t, int>{ port, 1 };
         args->requests_list.push_back( node );
         auto it_end = args->requests_list.end();
         args->requests_map[ port ] = --it_end;

         IP_packet SYN_packet;  // TODO: implement a clear function
         SYN_packet.setup_packet( &target );

         if ( sendto( ready_skt, SYN_packet.buffer(), SYN_packet.size(), 0, 
                      (const struct sockaddr*)&target, 
                      sizeof( struct sockaddr ) ) < 0 ) {
            perror( "sendto()" );
            exit( EXIT_FAILURE );
         }

         port += 1;
      }
   
      if ( pthread_mutex_unlock( &args->requests_mutex ) != 0 ) {
         perror( "pthread_mutex_unlock()" );
         exit( EXIT_FAILURE );
      }
   }
   std::cout << "port: " << port << std::endl;

   close( epollfd );
   for ( int skt : raw_skts ) {
      close( skt );
   } 
}
      
void snoop_network( std::stop_token stopToken, 
                    std::list<thread_arguments>::iterator args ) {
   int epollfd;
   const uint16_t MAX_EVENTS = 16; // TODO: change this
   struct epoll_event ev, events[ MAX_EVENTS ];

   if ( ( epollfd = epoll_create1( 0 ) ) == -1 ) {
      perror( "epoll_create1()" );
      exit( EXIT_FAILURE );
   }
   ev.events = EPOLLIN;
   
   std::vector<int> raw_skts;
   int on = 1;
   for ( int i=0; i < MAX_EVENTS; ++i ) {
      int skt = socket( AF_INET, SOCK_RAW, IPPROTO_TCP );
      if ( skt < 0 ) {
         perror( "socket()" );
         exit( EXIT_FAILURE ); 
      }
      // Set the socket file descriptor to non-blocking
      int flags = fcntl( skt, F_GETFL, 0 );
      if ( flags == -1 ) {
         perror( "fcntl()" );
         exit( EXIT_FAILURE );
      }
      flags |= O_NONBLOCK;
      if ( fcntl( skt, F_SETFL, flags ) == -1 ) {
         perror( "fcntl()" );
         exit( EXIT_FAILURE );
      }

      // Set the IP_HDRINCL option so we can write our own IP header
      setsockopt(skt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
      raw_skts.push_back( skt );

      // Add the skt to the monitored list
      ev.data.fd = skt;
      if ( epoll_ctl( epollfd, EPOLL_CTL_ADD, skt, &ev ) == -1 ) {
         perror( "epoll_ctl()" );
         exit( EXIT_FAILURE );
      }
   }

   ssize_t recvd_bytes;
   ssize_t buffersize = 65535; // Max IP packet size
   char buffer[ buffersize ];

   struct sockaddr src_addr;
   socklen_t addrlen = sizeof( struct sockaddr );

   struct iphdr* ip_header;
   struct tcphdr* tcp_header;
   while ( !stopToken.stop_requested() ) {
      int fd_count = epoll_wait( epollfd, events, MAX_EVENTS, -1 );
      if ( fd_count == -1 ) {
         perror( "epoll_wait()" );
         exit( EXIT_FAILURE );
      }
      
      if ( pthread_mutex_lock( &args->requests_mutex ) != 0 ) {
         perror( "pthread_mutex_lok()" );
         exit( EXIT_FAILURE );
      }
      for ( int i=0; i < fd_count; ++i ) {
         // TODO: refine this part
         if ( args->requests_list.empty() ) {
            // args->requests_cv.notify_one();
            // break;
         }

         int ready_skt = events[i].data.fd;

         memset( buffer, 0, buffersize );
         if ( recvfrom( ready_skt, buffer, buffersize, 0, 
                        &src_addr, &addrlen ) < 0 ) {
            perror( "recvfrom()" );
            exit( EXIT_FAILURE );
         }
   
         ip_header = (struct iphdr*)buffer;
         tcp_header = (struct tcphdr*)( buffer + sizeof( struct iphdr ) );
   
         // If the packet is from one of the target hosts
         if ( host_requests.contains( ip_header->saddr ) ) {
            // If it's a reply to one of the SYN packets that were sent
            if ( args->requests_map.contains( tcp_header->source ) ) {
               auto& it = args->requests_map[ tcp_header->source ];
               args->requests_list.erase( it );
               args->requests_map.erase( tcp_header->source );
            }
            // Check if its an ACK to one of the SYN packets that were sent.
            if (  ( tcp_header->syn == 1 ) && 
                  ( tcp_header->ack == 1 ) ) {
               host_open_ports_mutex.lock();
               host_open_ports[ ip_header->saddr ].insert( tcp_header->source );
               host_open_ports_mutex.unlock();
            }
         }
      }
      if ( pthread_mutex_unlock( &args->requests_mutex ) != 0 ) {
         perror( "pthread_mutex_unlock()" );
         exit( EXIT_FAILURE );
      }
   }
   close( epollfd );
   for ( int skt : raw_skts ) {
      close( skt );
   } 
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