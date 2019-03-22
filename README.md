# Logstash Plugin - public_ip

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

This Logstash filter plugin is used to determine ip version and if the ip address is public.

The plugin uses the following cidr ranges to determine if the ipaddress is in a non-public range.
```
# NON-PUBLIC REASONS
# ---------------
# 0.0.0.0/8 = RFC1700: reserved as a source address only
# 10.0.0.0/8 = RFC1918: reserved for private networking
# 100.64.0.0/10 = RFC6598: reserved for service provider shared address space but may be used in a manner similiar to RF1918
# 127.0.0.0/8 = RFC1112: assigned for use as the Internet host loopback address
# 169.254.0.0/16 = RFC3927: used for link-local addressing in Internet Protocol Version 4
# 172.16.0.0/12 = RFC1918: reserved for private networking
# 192.0.0.0/24 = RFC6890: IETF Protocol Assignments
# 192.0.0.8/32 = RFC7600: IPv4 dummy address
# 192.0.2.0/24 = RFC5737: Assigned as TEST-NET-1, documentation and examples
# 192.31.196.0/24 = RFC7535: AS112-v4
# 192.52.193.0/24 = RFC7450: AMT
# 192.88.99.0/24 = RFC7526: Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16
# 192.168.0.0/16 = RFC1918: reserved for private networking
# 198.18.0.0/15 = RFC2544: Used for benchmark testing of inter-network communications between two separate subnets
# 198.51.100.0/24 = RFC5737: Assigned as TEST-NET-2, documentation and examples
# 203.0.113.0/24 = RFC5737: Assigned as TEST-NET-3, documentation and examples
# 224.0.0.0/4 = RFC1112: In use for IP multicast (Former Class D network)
# 240.0.0.0/4 = RFC6890: Reserved for future use. (Former Class E network) 
# 255.255.255.255/32 = RFC8190: Reserved for the limited broadcast destination address
# fc00::/7 = RFC4193: Unique Local Address
# fe80::/10 = RFC4291: Link-Local Address
# ff00::/8 = RFC4291: Multicast Address
# 2001:db8::/32 = RFC3849: Addresses used in documentation and example source code
# 2001:20::/28 = RFC7343: Prefix for Overlay Routable Cryptographic Hash Identifiers Version 2
# ::1/128 = RFC8190: Loopback address to local host
# ::/128 = RFC8190: Unspecified address
# 100::/64 = RFC6666: Discard Prefix
# 64:ff9b::/96 = RFC6052: IPv4/IPv6 translation
```

## Installation
```
bin/logstash-plugin install logstash-filter-public_ip
```
- Start Logstash and proceed to test the plugin

#### USAGE
```
filter {
  public_ip {
    source => "src_ip"
    target_ipv => "src_ipv"
    target_pub_ip => "src_public_ip"
  }
}
```
