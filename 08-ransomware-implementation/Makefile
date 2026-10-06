all: audit_logger audit_monitor 


audit_logger: audit_logger.c 
	gcc -Wall -fPIC -shared -o audit_logger.so audit_logger.c -lcrypto -ldl 


audit_monitor: audit_monitor.c 
	gcc -Wall -O2 -o audit_monitor audit_monitor.c -lcrypto


clean:
	rm -rf audit_logger.so
	rm -rf audit_monitor

