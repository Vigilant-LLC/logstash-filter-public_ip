# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'ipaddr'

# NON-PUBLIC CIDRS THIS PLUGIN USES TO VERIFY IF THE IP IS PUBLIC OR PRIVATE
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

class LogStash::Filters::PublicIp < LogStash::Filters::Base

  # configure this filter from your Logstash config.
  #
  # filter {
  #   public_ip {
  #     source => "src_ip"
  #     target_ipv => "src_ipv"
  #     target_pub_ip => "src_public_ip"
  #   }
  # }
  #
  config_name "public_ip"

  # Field with source ip address
  config :source, :validate => :string, :required => true
  # target field to put ip vesrion data
  config :target_ipv, :validate => :string, :default => "ip_version"
  # target field to put ip vesrion data
  config :target_pub_ip, :validate => :string, :default => "public_ip"
  # tag invalid ip
  config :tag_on_invalid_ip, :validate => :array, :default => ["_invalid_ip"]

  public
  def register
    # NON-PUBLIC CIDR ARRAY
    @cidr = [
      "0.0.0.0/8",
      "10.0.0.0/8",
      "100.64.0.0/10",
      "127.0.0.0/8",
      "169.254.0.0/16",
      "172.16.0.0/12",
      "192.0.0.0/24",
      "192.0.0.8/32",
      "192.0.2.0/24",
      "192.31.196.0/24",
      "192.52.193.0/24",
      "192.88.99.0/24",
      "192.168.0.0/16",
      "198.18.0.0/15",
      "198.51.100.0/24",
      "203.0.113.0/24",
      "224.0.0.0/4",
      "240.0.0.0/4",
      "255.255.255.255/32",
      "fc00::/7",
      "fe80::/10",
      "ff00::/8",
      "2001:db8::/32",
      "2001:20::/28",
      "::1/128",
      "::/128",
      "100::/64",
      "64:ff9b::/96"
    ]
  end # def register
  
  public
  def filter(event)
    begin
      ip = event.get(@source)
      srcip = IPAddr.new(ip)
      validip = true
    rescue
      validip = false
    end
    if validip == true
      # ip version
      if srcip.ipv4?
        ipv = '4'
      elsif srcip.ipv6?
        ipv = '6'
      end
      event.set("#{@target_ipv}", ipv)

      # public ip check
      pubip = true
      @cidr.each do |p|
        cidr = IPAddr.new(p)
        if cidr.include?(srcip)
          pubip = false
        end
      end
      event.set("#{@target_pub_ip}", pubip)
    end

    # Tag event if invalid ip
    tag_invalid_ip(event) if validip == false
    # filter_matched should go in the last line of our successful code
    filter_matched(event) if validip == true
  end # def filter

  def tag_invalid_ip(event)
    @logger.debug? && @logger.warn("Invalid IP #{event.get(@source)}", :event => event)
    @tag_on_invalid_ip.each{|tag| event.tag(tag)}
  end # def tag_invalid_ip

end # class LogStash::Filters::PublicIp
