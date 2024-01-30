#ifndef scanner_h
#define scanner_h

#include <netinet/in.h>
#include <stop_token>

#include <unordered_map>
#include <mutex>
#include <thread>

/* Related to the snooping thread*/
extern std::unordered_map<uint64_t, bool> open_ports;
extern  std::mutex open_ports_mutex;
extern std::unordered_map<uint64_t, bool> pending_requests; // addr + port
extern std::mutex pending_requests_mutex;

bool send_SYN( int, const struct sockaddr_in* );
const struct sockaddr_in get_localhost_addr();
void snoop_network( std::stop_token );

#endif // scanner_h#include "scanner.h"