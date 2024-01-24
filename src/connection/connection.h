#include <iostream>
#include <string>
#include <memory>

#include <netdb.h>
#include <string.h>
#include <unistd.h>

int connect_to_host( const std::string&, const std::string& );
void setup_local_server( const std::string& );