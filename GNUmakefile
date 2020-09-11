default: logstest.out logsinit.out

logstest.out: logstest.o logstor.o
	cc -g -o logstest.out logstest.o logstor.o

logstor.o: logstor.c logstor.h GNUmakefile
	cc -g -c -DEXIT_ON_PANIC -Wall logstor.c

logstest.o: logstest.c logstor.h GNUmakefile
	cc -g -c -Wall logstest.c

clean:
	rm *.o *.out *.core ggatelog ggatelog.debug ggatelog.full

logsinit.o: logsinit.c logstor.h GNUmakefile
	cc -g -c -Wall logsinit.c

logsck.o: logsck.c logstor.h GNUmakefile
	cc -g -c -Wall logsck.c

logsinit.out: logsinit.o logstor.o
	cc -g -o logsinit.out logsinit.o logstor.o

logsck.out: logsck.o logstor.o
	cc -g -o logsck.out logsck.o logstor.o

