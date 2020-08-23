# Lua Hook on kTLS
## Overview
Kernel TLS is introduced by facebook researcher in [this paper](https://netdevconf.info/1.2/papers/ktls.pdf), the feature is also supported since Linux 4.13. By moving encryption and decryption to kernel, using `sendfile` for data exchange claims a significant improvement in 99th percentile performance from the paper.

[Lunatik](https://github.com/luainkernel/lunatik) is a kernel script library which allows us to execute Lua scripts inside the Linux kernel, previous GSoC project also made use of this, such as [XDPLua](https://github.com/VictorNogueiraRio/linux), [Lunatik RCU binding](https://github.com/caio-messias/lunatik) and [Lunatik Socket Library](https://github.com/tcz717/lunatik).

Since Lua is more easy to use, add support for TLS hook can benefit some application like http server. That enable user to add more modules that written in Lua that works in kernel space to avoid some overhead such as buffer copy and priority change.

Lua Hook on kTLS is a project, initially developed during Google Summer of Code 2020, that aims to combine the benefit of kTLS and Lua kernel script so we can use the Lua script without much modification to current user code and have acceptable overhead.

The goal of Lua Hook on kTLS is to modify the `tls` module in linux kernel to add Lua hook inside, this allows us to execute Lua script through Lunatik after receiving and decrypting data. We also write a simple https server that serving only static file which make use of Lua script through the hook to parse the request and using `sendfile` to send the static file back to user.

For this project, we are using Linux kernel version 5.4.0-42, lower version that support kTLS could work as well but not tested.

## Use case
First you need to initialize the ULP and kTLS by the [Linux document](https://www.kernel.org/doc/html/latest/networking/tls.html), currently only GNUTLS support getting the parameters of the tls connection. In GNUTLS you can use

```
gnutls_record_get_state(session, 1, &mac_key, &iv, &cipher_key, seq_number);
gnutls_record_get_state(session, 0, &mac_key, &iv, &cipher_key, seq_number);
```

to get the read/write key for initialize the kTLS. And use

```
setsockopt(client, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info))
setsockopt(client, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info))
```

to set the crypto infomation.

Then you may add Lua script and set `recv` entrance through `setsockopt`:

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

## Implementation
The kTLS ULP operates in the network system calls, it does the encryption / decryption transparently in the system calls like `recv`, `send` or `sendfile`. So in user space we could send/receive plain text without realizing the TLS layer. The hook will operate at the end of `recvmsg` to use the lunatik in kernel script library and execute the Lua script with the decrypted message received. User then can interact with the hook by `getsockopt` and `setsockopt`.

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
- The implementation is not yet optimized to avoid copies.

## Future work
- Zero copy support.
- Support response send directly in lua script so we can escape from c-style code.

## Project PR detail
- [PR1](https://github.com/luainkernel/ktls/pull/1) Add `setsockopt` support for the hook.
- [PR2](https://github.com/luainkernel/ktls/pull/2) Add `recv` hook and improve test.
- [PR3](https://github.com/luainkernel/ktls/pull/3) Change from openssl to gnutls for bugs in openssl ktls.
- [PR4](https://github.com/luainkernel/ktls/pull/4) Add http server support and benchmark.
- [PR6](https://github.com/luainkernel/ktls/pull/6) Detailed benchmark for different combination of settings.
- [PR8](https://github.com/luainkernel/ktls/pull/8) Final report.