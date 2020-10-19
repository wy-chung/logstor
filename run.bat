# create the ggate device
./ggatelog init /dev/da4s1
./ggatelog create /dev/da4s1

# initialize the file system
newfs /dev/ggate0
tunefs -t enable /dev/ggate0
mount /dev/ggate0 /mnt

# copy the src
/usr/bin/time cp -R /nfs/freebsd.wyc /mnt

# build the kernel
cd /mnt/freebsd.wyc
/usr/bin/time make MAKEOBJDIRPREFIX=/mnt/obj kernel KERNCONF=GENERIC

# do file system check
fsck /dev/ggate0

# delete the folders
/usr/bin/time rm -R /mnt/obj
/usr/bin/time rm -R /mnt/freebsd.wyc

# destroy the ggate device
umount /mnt
./ggatelog destroy -u 0

