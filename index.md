# Lua Hook on kTLS
## Overview
Kernel TLS is introduced by facebook researcher in [this paper](https://netdevconf.info/1.2/papers/ktls.pdf), the feature is also supported since Linux 4.13. By moving encryption and decryption to kernel, using `sendfile` for data exchange claims a significant improvement in 99th percentile performance from the paper.

[Lunatik](https://github.com/luainkernel/lunatik) is a kernel script library which allows us to execute Lua scripts inside the Linux kernel, previous GSoC project also made use of this, such as [XDPLua](https://github.com/VictorNogueiraRio/linux), [Lunatik RCU binding](https://github.com/caio-messias/lunatik) and [Lunatik Socket Library](https://github.com/tcz717/lunatik).

Since Lua is more friendly towards memory and string compared to C that you need to be careful about memory, it may be more convenient for some applications like http server, but we need to make sure doing so won't introduce too much overhead.

Lua Hook on kTLS is a project, initially developed during Google Summer of Code 2020, that aims to combine the benefit of kTLS and Lua kernel script so we can use the Lua script without much modify to current user code and have acceptable overhead.

The goal of Lua Hook on kTLS is to modify the `tls` module in linux kernel to add Lua hook inside, this allows us to execute Lua script through Lunatik after receiving and decrypting data. We also write a simple https server which make use of Lua script through the hook to parse the request and using `sendfile` to send the static file back to user.

For this project, we are using Linux kernel version 5.4.0-42, lower version that support kTLS could work as well but not tested.

## Use case
First you need to initialize the ULP and kTLS by the [Linux document](https://www.kernel.org/doc/html/latest/networking/tls.html), currently only GNUTLS support getting the parameters of the tls connection. Then you may add Lua script and set `recv` entrance through `setsockopt`:

```
setsockopt(sock, SOL_TLS, TLS_LUA_LOADSCRIPT, script, strlen(script) + 1);
setsockopt(sock, SOL_TLS, TLS_LUA_RECVENTRY, "recv", strlen("recv") + 1);
```

Currently we support the `recv` hook and you can use like this in Lua script:

```
function recv(m)
    ...
    return code, file
end
```

The Lua script runs before the `recv` system call return and `m` is just the return value of the system call. You can parse the message received and return the code and file so that the user space can get these through `getsockopt`:

```
getsockopt(sock, SOL_TLS, TLS_LUA_CODE, ...);
getsockopt(sock, SOL_TLS, TLS_LUA_FILE, ...);
```

## Benchmark
We do benchmark through the simple https serve we write with a lighttpd server, depending on the file size, our delay time is from 200% to 80% compared to that of lighttpd, because we are not doing optimization(such as caching files and so on) for small file. We also do benchmark for combination of userspace or kernel space Lua script and using kTLS or the traditional one. The result shows that userspace lua and kTLS does a little better than kernel space Lua, for there are buffer copy in the hook to Lunatik and Lunatik itself. This left further optimization in the future.

You can refer to detail benchmark [here](https://github.com/luainkernel/ktls/tree/master/benchmark).

## Installation
To install the modified tls module and run test server, you can clone this [github repository](https://github.com/luainkernel/ktls), and run these command:

```
make
sudo insmod lunatik/lunatik.ko
sudo insmod tls.ko
cd test
# If you want to change server mode, modify KTLS and USERLUA macro in test_server.c
make
./test_server 12345 .
curl -v -k https://localhost:12345/hook.lua --output -
```

For more option and usage, please refer to the README in the repository.

## Limitations
- For now, we only support recv hook and the http style response.
- Because of some unknown bugs in tls module or ssl library(such as [openssl](https://github.com/openssl/openssl/issues/12082)), the sender must send message first after tls negotiation, otherwise the connection may be broken randomly.
- The hook and lunatik will do lots of buffer copy so far, the performance may be worse than expected in some cases.

## Future work
- Optimize the copy in hook and lunatik so we can realize zero copy.
- Support response send directly in lua script so we can escape from c-style code.
