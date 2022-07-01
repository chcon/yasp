# yasp
YASP - Yet Another (SOCKS) Proxy, but with UDP support for SOCKS-5

## What it is
A very simple SOCKS proxy server based on Go. It supports SOCKS-4 and SOCKS-5.
Supplementary to most of the already existing proxy implementations it also supports UDP connections via SOCKS-5. This facilitates forwarding of UDP traffic without the need for cumbersome workarounds like using socat to convert UDP to TCP on client side, then send the TCP packets to the proxy, and then revert the traffic back to UDP before it leaves the proxy for the destination.

## Acknowledement
This is not written from scratch. I combined an existing SOCKS proxy implementation and an existing UDP forwarder implementation and added the code to handle UDP traffic via SOCKS-5 to both.
Acknowledgements go to the maintainers of these two projects:
+ https://github.com/fangdingjun/socks-go
+ https://github.com/1lann/udp-forward

## Usage

```
$ ./yasp -h
Usage of ./yasp:
  -p string
        Socks proxy bind address [IP:port] (default "127.0.0.1:3180")
  -t int
        Timeout [seconds] (default 300)
  -u string
        UDP forwarder bind address [IP:port] (default "127.0.0.1:49111")
```

In this example YASP is running on 192.168.1.100, with the SOCKS proxy running on port 3180, and the UDP forwarder running on port 41234, and the timeout for idle connections in the UDP forwarder is set to one hour:

```
$ ./yasp -p 192.168.1.100:3180 -u 192.168.1.100:41234 -t 3600
2022/07/01 10:10:56 Proxy connection from 192.168.1.20:24531 
2022/07/01 10:10:57 target address in client's packet is 0.0.0.0:0 (may be 0.0.0.0:0 for UDP port association requests)
2022/07/01 10:10:57 Starting UDP Port Association
2022/07/01 10:10:57 Registered new client with forwarder:  192.168.1.20
2022/07/01 10:10:57 New source connected:  192.168.1.20:24307->10.10.10.200:1337
2022/07/01 10:11:12 Currently connected:  192.168.1.20:24307->10.10.10.200:1337
2022/07/01 10:11:42 Currently connected:  192.168.1.20:24307->10.10.10.200:1337
```

## Limitations
+ IPv6 and URL support is not yet finalized, especially the UDP forwarder bind address currently must be an IPv4 address.
+ Currently no authentication; the bind ports on the proxy server should be restricted by firewall rules to single IP addresses or small subnets

## TODO
+ Unit tests (shame on me)
+ Finalize IPv6 support
+ Implement proxy authorization
+ Register clients from the proxy to the forwarder
+ Improve logging
