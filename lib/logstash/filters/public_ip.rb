# encoding: utf-8
require "logstash/filters/base"
require "logstash/filters/public_ip"
require "logstash/filters/ipvlookup"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::PublicIp < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
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
  end
  

  public
  def filter(event)
    ip = event.get(@source)
    lookup = Ipvlookup.new(ip)
    validip = lookup.validip
    if validip == true
      ipv = lookup.ipversion
      event.set("#{@target_ipv}", ipv)
      pubip = lookup.pubip
      event.set("#{@target_pub_ip}", pubip)
    end
    # Tag event if invalid ip
    tag_invalid_ip(event) if validip == false
    # filter_matched should go in the last line of our successful code
    filter_matched(event) if validip == true
  end # def filter

  def tag_invalid_ip(event)
    @logger.debug? && @logger.debug("Invalid IP #{event.get(@source)}", :event => event)
    @tag_on_invalid_ip.each{|tag| event.tag(tag)}
  end

end # class LogStash::Filters::PublicIp
