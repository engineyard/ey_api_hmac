require 'ey_api_hmac/base_connection'
require 'ey_api_hmac/api_auth'
require 'ey_api_hmac/sso'

module EY
  module ApiHMAC
    require 'openssl'

    def self.sign!(env, key_id, secret, strict = false)
      env["HTTP_AUTHORIZATION"] = "AuthHMAC #{key_id}:#{signature(env, secret, strict)}"
    end

    def self.canonical_string(env, strict = false)
      parts = []
      adder = Proc.new do |var|
        unless env[var]
          raise HmacAuthFail, "'#{var}' header missing and required in #{env.inspect}"
        end
        parts << env[var]
      end
      adder["REQUEST_METHOD"]
      adder["CONTENT_TYPE"]
      if env["HTTP_CONTENT_MD5"]
        adder["HTTP_CONTENT_MD5"]
      else
        parts << generated_md5(env)
      end
      adder["HTTP_DATE"]
      adder["PATH_INFO"]
      parts.join("\n")
    end

    def self.signature(env, secret, strict = false)
      base64digest(canonical_string(env, strict), secret)
    end

    def self.base64digest(data,secret)
      digest = OpenSSL::Digest::Digest.new('sha1')
      [OpenSSL::HMAC.digest(digest, secret, data)].pack('m').strip
    end

    class HmacAuthFail < StandardError; end

    def self.authenticate!(env, &lookup)
      rx = Regexp.new("AuthHMAC ([^:]+):(.+)$")
      if md = rx.match(env["HTTP_AUTHORIZATION"])
        access_key_id = md[1]
        hmac = md[2]
        secret = lookup.call(access_key_id)
        unless secret
          raise HmacAuthFail, "couldn't find auth for #{access_key_id}"
        end
        unless hmac == signature(env, secret)
          raise HmacAuthFail, "signature mismatch"
        end
      else
        raise HmacAuthFail, "no authorization header"
      end
    end

    def self.authenticated?(env, &lookup)
      begin
        authenticate!(env, &lookup)
        true
      rescue HmacAuthFail => e
        false
      end
    end

    private

    def self.generated_md5(env)
      request_body = env["rack.input"].read
      env["rack.input"].rewind
      OpenSSL::Digest::MD5.hexdigest(request_body)
    end

  end
end