# ktls
Kernel version: 5.4.44

    make
    sudo insmod lunatik/lunatik.ko
    sudo insmod tls.ko
    cd test
    # If you want to change server mode, modify KTLS and USERLUA macro in test_server.c
    make
    ./test_server 12345 .
    curl -v -k https://localhost:12345/hook.lua --output -

You will receive lua script in http response.

You can also enable `TCP_CORK` with argument `-c`