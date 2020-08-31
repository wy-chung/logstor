kldunload -v geom_logstor.ko
kldload -v ./geom_logstor.ko
kldstat|fgrep geom_logstor.ko
objdump --section-headers geom_logstor.ko|fgrep text
# (gdb) add-symbol-file geom_logstor.kld 0xc0ae22d0
