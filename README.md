# logstor - Log-Structured GEOM storage Layer

## Introduction
Logstor is a log-structured user-level FreeBSD GEOM layer that uses the same 
principle of log-structured file system. That is, it treats the storage as a log 
and only appends data to the end of the log. Like log-structured file system, it has 
the ability to translate random writes from the file system above into sequential writes 
to the underlying disk.<br/>
I have tested it by doing kernel build on logstor. The input source files and the 
output object files are all directed to logstor in kernel build test. Compared to 
ggatel, the performance is almost the same as ggatel but gets worse when garbage 
collection is triggered.<br/>

## Build the program
Currently it is implemented as a user-level GEOM. To build the program, first 
download the program to src/sys/geom/logstor and run 'make'. The make program 
will then generate the executable file 'ggatelog'.

## Run the program
First you have to run 'ggatelog init device_name' to initialize the underlying device 
and then run 'ggatelog create device_name' to create the logstor device (i.e. 
/dev/ggate0). After that the log-structured device (/dev/ggate0) can be mounted.

## Memo
'run.bat' is a sample batch file. It shows how to create a logstor device, create a 
file system on the logstor device, copy the src files to the file system and build 
the kernel on the file system.
