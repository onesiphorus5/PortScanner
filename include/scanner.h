#ifndef scanner_h
#define scanner_h

#include <netinet/in.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <stop_token>
#include <thread>

/* Defined in main.cc */
extern std::unordered_set<uint32_t> pending_requests; // hosts
extern std::unordered_map<uint32_t, std::unordered_set<uint16_t>> open_ports;
extern  std::mutex open_ports_mutex;

/* Defined in main.cc*/
extern const uint16_t MAX_PORT_COUNT;

void send_SYN_packets( uint32_t, uint16_t, uint16_t, uint16_t );
const struct sockaddr_in get_localhost_addr();
void snoop_network( std::stop_token );

#endif // scanner_h#include "scanner.h"