# ktls
Kernel version: 5.4.44

    make
    sudo insmod lunatik/lunatik.ko
    sudo insmod tls.ko
    ./test 4444
    sudo dmesg

You will see "hello world" in message.