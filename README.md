# ebpf-fw
A simple demo of building a network firewall with eBPF with the help of https://github.com/aya-rs/aya


This demo loads `XDP` eBPF application and does a few things:
 - parses Ethernet protocol
 - if it is IPv6 - drop it
 - if it is IPv4 - print SRC and DST for TCP or UDP only


To run it to drop all packets for 80 comming from <your IP> `RUST_LOG=info cargo xtask run  -- -i enp0s3 -p 80 -s <your IP>`


```
Options:
  -i, --iface <IFACE>            [default: enp0s3]
  -s, --source-ips <SOURCE_IPS>
  -p, --port <PORT>
  -h, --help                     Print help
```
