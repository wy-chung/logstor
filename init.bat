#!/bin/tcsh

setenv target /dev/da4s2

dd if=/dev/zero of=$target bs=32k count=1
./ggatelog create $target

