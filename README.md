This is a TCP port scanner. Given a host IP (\<host\>) and the PORT (\<port\>) to scan, it tells you if the port is OPEN or NOT.

How to run the program:
1. Inside the root directory build the program with this make command: "make portscanner"
2. Run the program with the following command line arguments:
	a. --host :list of hosts. This argument is mandatory
	b. --port : port range. This argument is optional. Default value : "1-1000"
	c. --parallel : number of outstanding scan requests per thread. This argument is optional. Default value: "8"
	d. --timeout : number of milliseconds to wait for SYN packets sent to be received. This argument is optional. 
						Default value: "200".

Example:
	$ sudo ./portscanner --host=127.0.0.1 port=1-1000 --parallel=8

