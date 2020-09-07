# ggatelog - Log-Structured GEOM storage Layer

## Introduction
Ggatelog is a log-structured (FreeBSD) GEOM layer that uses that same principle of log-structured file system. That is, it treats the storage as a log and only appends data to the end of the log. Like log-structured file system, it has the ability to translate random writes from the file system above into sequential writes to the underlying disk.<br/>
I have tested it by doing kernel build on ggatelog. The input source files and the output object files are all directed to ggatelog in kernel build test. Compared to 'ggatel, The performance is almost the same as 'ggatel' but gets worse when garbage collection is triggered.<br/>
Currently there is still some bug not fixed in garbage collection.

## Build the program
Currently it is implemented by using the user-level GEOM, i.e. ggate. To build the program, first download the program to src/sys/geom/logstor and run 'make'. The make program will then generate the executable file 'ggatelog'.

## Run the program
First you have to run 'init.bat' to initialize the underlying device and then run 'create.bat' to create the gate device (i.e. /dev/ggate0). After that the log-structured device is mounted under '/mnt'.
