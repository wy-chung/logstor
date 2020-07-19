#!/bin/tcsh

setenv target /dev/ada1
#setenv target /dev/da4b

dd if=/dev/zero of=$target bs=32k count=1

