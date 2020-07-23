# ktls
Kernel version: 5.4.44

    make
    sudo insmod lunatik/lunatik.ko
    sudo insmod tls.ko
    cd test
    make
    ./test_server 4444
    ./test_client 127.0.0.1 4444
    sudo dmesg

You will see lua script output in message.