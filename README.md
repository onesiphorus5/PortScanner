This is a TCP port scanner. Given a host IP (or list of IPs) and a TCP port range to scan, it prints which TCP ports are open.

How to run the program:
1. Inside the root directory build the program with this make command: "make portscanner"
2. Run the program with the following command line arguments:<br \>
   a. --host :list of hosts. This argument is mandatory<br \>
   b. --port : port range. This argument is optional. Default value : "1-1000"<br \>
   c. --parallel : number of outstanding scan requests per thread. This argument is optional. Default value: "8"<br \>
   d. --timeout : number of milliseconds to wait for SYN packets sent to be received. This argument is optional.<br \>
                  Default value: "200".<br \><br \>

Example:<br \>
	$ sudo ./portscanner --host=127.0.0.1 port=1-1000 --parallel=8
