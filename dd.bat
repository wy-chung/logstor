#!/bin/tcsh

setenv target /dev/da4s1

dd if=/dev/zero of=$target bs=32k count=1

