#ifndef cmdline_parser_h
#define cmdline_parser_h

#include <iostream>
#include <vector>

class ScanRequest {
private:
   std::string _host;
   std::string _port;

public:
   ScanRequest( const std::string& h, const std::string& p ) :
      _host{h}, _port{p} {}

   const std::string& host() const { return _host; }
   const std::string& port() const { return _port; }
};

class CmdLineOptions {
private:
   std::vector<ScanRequest> _scan_requests;
   
public:
   const std::vector<ScanRequest>& scan_requests() const { return _scan_requests; }

   void add_request( const std::string& host, const std::string& port ) {
      _scan_requests.emplace_back( host, port );
   }
};

CmdLineOptions cmdline_parse( int argc, const char* argv[] );

#endif // cmdline_parser_h