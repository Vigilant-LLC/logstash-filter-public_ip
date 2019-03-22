# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/public_ip"

describe LogStash::Filters::PublicIp do
  describe "ipversion" do
    let(:config) do <<-CONFIG
      filter {
        public_ip {
          source => "ip"
          target_ipv => "ipv"
          target_pub_ip => "pubip"
        }
      }
    CONFIG
    end
    
    sample("ip" => "10.0.0.1") do
      expect(subject.get("ipv")).to eq('4')
    end
  end

  describe "invalid ip" do
    let(:config) do <<-CONFIG
      filter {
        public_ip {
          source => "ip"
          target_ipv => "ipv"
          target_pub_ip => "pubip"
        }
      }
    CONFIG
    end

    sample("ip" => "10000.0.0.1") do
      expect(subject.get("tags")).to include("_invalid_ip")
    end
  end

  describe "ipv4 pubip false" do
    let(:config) do <<-CONFIG
      filter {
        public_ip {
          source => "ip"
          target_ipv => "ipv"
          target_pub_ip => "pubip"
        }
      }
    CONFIG
    end

    sample("ip" => "10.0.0.1") do
      expect(subject.get("pubip")).to eq(false)
    end
  end

  describe "ipv6 pubip true" do
    let(:config) do <<-CONFIG
      filter {
        public_ip {
          source => "src_ip"
          target_ipv => "[src][ipv]"
          target_pub_ip => "[src][pubip]"
        }
      }
    CONFIG
    end

    sample("src_ip" => "2606:4700:4700::1001") do
      expect(subject.get("[src][pubip]")).to eq(true)
    end
  end

  describe "no valid source" do
    let(:config) do <<-CONFIG
      filter {
        public_ip {
          source => "ip"
          target_ipv => "ipv"
          target_pub_ip => "pubip"
        }
      }
    CONFIG
    end

    sample("ip" => nil) do
      expect(subject.get("tags")).to include("_invalid_ip")
    end
  end

end
