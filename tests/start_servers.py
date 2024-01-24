#!/usr/bin/env python3

import sys
import os
import subprocess
import time

test_server_path = "./tests/test_server"

if __name__ == "__main__":
   if len( sys.argv ) < 2:
      sys.exit( "Expecting at least one port" )

   if not os.path.exists( test_server_path ) or \
      not os.access( test_server_path, os.X_OK ):
      sys.exit( "test_server executable is missing" )

   server_processes = []
   # Start test servers
   for port in sys.argv[1:]:
      if int( port ) <= 1024:
         message = "port {} is less or equal to 1024, skipping the port"
         print( message.format( port ) )
         continue
      process = subprocess.Popen( [test_server_path, port ] )      
      server_processes.append( process )
   
   time.sleep( 10 )

   # Start portscanner
   # portscanner_process = subprocess.Popen( ["./portscanner"] )

   # Chek if the ports we have passed in the arguments have been scanned