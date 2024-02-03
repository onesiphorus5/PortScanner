#ifndef scanner_h
#define scanner_h

#include <netinet/in.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <vector>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <stop_token>
#include <mutex>
#include <condition_variable>

using map_type = std::unordered_map<uint16_t, 
                           std::list< std::pair<uint16_t, int> >::iterator>;
struct thread_arguments {
   thread_arguments( uint32_t addr, uint16_t s_port, uint16_t l_port, 
                     uint16_t _parallel, int _timeout, 
                     pthread_mutex_t m, pthread_cond_t c, pthread_mutex_t c_m ) :
      target_addr{ addr }, start_port{ s_port }, last_port{ l_port },
      parallel{_parallel}, timeout{_timeout},
      requests_mutex{m}, requests_cv{c}, requests_cv_mutex{c_m} {
         pthread_mutex_init( &requests_mutex, NULL );
         pthread_cond_init( &requests_cv, NULL );
         pthread_mutex_init( &requests_cv_mutex, NULL );
      }
   
   uint32_t target_addr;
   uint16_t start_port;
   uint16_t last_port;
   uint16_t parallel;
   int timeout; // in milliseconds
   map_type requests_map;
   std::list< std::pair<uint16_t, int> > requests_list;
   pthread_mutex_t requests_mutex;
   pthread_cond_t requests_cv;
   pthread_mutex_t requests_cv_mutex;
};

// Defined in main.cc
extern std::list<thread_arguments> thread_args_list;

// Defined in main.cc
extern const uint16_t BATCH_SIZE;
extern const uint16_t MAX_PORT_COUNT;

extern std::unordered_set<uint32_t> host_requests; // hosts
extern std::unordered_map<uint32_t, 
                          std::unordered_set<uint16_t>> host_open_ports;
extern std::mutex host_open_ports_mutex;


void send_SYN_packets( std::list<thread_arguments>::iterator );
void snoop_network( std::stop_token, std::list<thread_arguments>::iterator ); 
const struct sockaddr_in get_localhost_addr();

#endif // scanner_h#include "scanner.h"