#ifndef scanner_h
#define scanner_h

#include "cmdline_parser.h"

bool send_SYN( int, const struct sockaddr_in*, const ScanRequest& );
bool recv_ACK( int, const ScanRequest& );

#endif // scanner_h