# create the ggate device
./ggatelog init /dev/da4s2
./ggatelog create /dev/da4s2

# initialize the file system
newfs /dev/ggate0
tunefs -t enable /dev/ggate0
mount /dev/ggate0 /mnt

# copy the src
/usr/bin/time -o /tmp/1 cp -R /nfs/freebsd-src-wyc /mnt

# build the kernel
cd /mnt/freebsd-src-wyc
/usr/bin/time -a -o /tmp/1 env MAKEOBJDIRPREFIX=/mnt/obj make kernel KERNCONF=GENERIC

# delete the obj folder
/usr/bin/time -a -o /tmp/1 rm -R /mnt/obj

# build the kernel
cd /mnt/freebsd-src-wyc
/usr/bin/time -a -o /tmp/1 env MAKEOBJDIRPREFIX=/mnt/obj make kernel KERNCONF=GENERIC

ls /mnt

# delete the obj folder
/usr/bin/time -a -o /tmp/1 rm -R /mnt/obj

# delete the src folder
/usr/bin/time -a -o /tmp/1 rm -R /mnt/freebsd-src-wyc

# do file system check
sleep 1
fsck /dev/ggate0

ls /mnt
cat /tmp/1

# destroy the ggate device
umount /mnt
./ggatelog destroy -u 0

