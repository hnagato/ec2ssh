require 'aws-sdk'
require 'ec2ssh/dotfile'

module Ec2ssh
  class AwsEnvNotDefined < StandardError; end
  class Hosts
    def initialize(dotfile, keyname)
      @dotfile = dotfile
      @ec2 = Hash.new do |h,region|
        key = dotfile.aws_key(keyname)
        raise AwsEnvNotDefined if key['access_key_id'].nil? || key['secret_access_key'].nil?
        h[region] = AWS::EC2.new(
          :ec2_endpoint      => "#{region}.ec2.amazonaws.com",
          :access_key_id     => key['access_key_id'],
          :secret_access_key => key['secret_access_key']
        )
      end
    end

    def all
      @dotfile['regions'].map {|region|
        process_region region
      }.flatten
    end

    private
      def process_region(region)
        instances(region).map {|instance|
          code = instance[:instance_state][:code]
          next nil if code.nil? || code != 16

          name_tag = instance[:tag_set].find {|tag| tag[:key] == 'Name' }
          next nil if name_tag.nil? || name_tag[:value].nil?
          name = name_tag[:value]
          
          dns_name = instance[:dns_name] ? instance[:dns_name] : instance[:ip_address]
          if(!dns_name && instance[:private_ip_address])
              is_private = true
              dns_name = instance[:private_ip_address]
              vpc_id = instance[:vpc_id]
          end
          next nil if dns_name.nil?
          
          pem = nil
          extparam = ""
          if(@dotfile['pems'])
            pem = @dotfile['pems'][region] ? @dotfile['pems'][region] : @dotfile['pems']['default']
          end
          extparam += pem ? "  IdentityFile " + pem + "\n" : ""
          user = nil
          if(@dotfile['users'])
            user = @dotfile['users'][region] ? @dotfile['users'][region] : @dotfile['users']['default']
          end
          extparam += user ? "  User " + user + "\n" : ""
          
          proxy_command = nil
          if(@dotfile['vpc'] && @dotfile['vpc']['proxy_commands'])
            proxy_command = @dotfile['vpc']['proxy_commands'][vpc_id] if is_private && vpc_id
          end
          extparam += proxy_command ? "  ProxyCommand " + proxy_command + "\n" : ""
          
          {:host => "#{name}", :dns_name => dns_name, :extparam => extparam}
        }.compact.sort {|a,b| a[:host] <=> b[:host] }
      end

      def instances(region)
        response = @ec2[region].instances.tagged('Name').filtered_request(:describe_instances)
        response[:instance_index].values
      end
  end
end
