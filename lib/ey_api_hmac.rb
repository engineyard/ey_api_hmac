require 'ey_api_hmac/base_connection'
require 'ey_api_hmac/api_auth'

module EY
  module ApiHMAC
    require 'openssl'

    def self.sign_for_sso(url, parameters, auth_id, auth_key)
      uri = URI.parse(url)
      raise ArgumentError, "use parameters argument, got query: '#{uri.query}'" if uri.query
      uri.query = parameters.sort.map {|e| e.map{|str| CGI.escape(str.to_s)}.join '='}.join '&'
      signature = CGI.escape(base64digest(uri.query.to_s, auth_key))
      uri.query += "&signature=#{signature}"
      uri.to_s
    end

    def self.verify_for_sso(url, auth_id, auth_key)
      uri = URI.parse(url)
      signature = CGI.unescape(uri.query.match(/&signature=(.*)$/)[1])
      signed_string = uri.query.gsub(/&signature=(.*)$/,"")
      base64digest(signed_string.to_s, auth_key) == signature
    end

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