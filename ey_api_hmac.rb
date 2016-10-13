require 'ey_api_hmac/authed_connection'
require 'ey_api_hmac/api_auth'
require 'ey_api_hmac/sso'

module EY
  module ApiHMAC
    require 'openssl'

    def self.sign!(env, key_id, secret)
      env["HTTP_AUTHORIZATION"] = auth_string(key_id, signature(env, secret))
    end

    def self.canonical_string(env, legacy = false)
      parts = []
      expect = Proc.new do |var|
        unless env[var]
          raise HmacAuthFail, "'#{var}' header missing and required in #{env.inspect}"
        end
        env[var]
      end
      parts << expect["REQUEST_METHOD"]
      parts << env["CONTENT_TYPE"]
      parts << generated_md5(env, legacy)
      parts << expect["HTTP_DATE"]
      if env["REQUEST_URI"]
        parts << URI.parse(env["REQUEST_URI"]).path
      else
        parts << (env["SCRIPT_NAME"] + expect["PATH_INFO"])
      end
      parts.join("\n")
    end

    def self.auth_string(key_id, signature)
      "AuthHMAC #{key_id}:#{signature}"
    end

    def self.signature(env, secret)
      base64digest(canonical_string(env), secret)
    end

    def self.signature_legacy(env, secret)
      base64digest(canonical_string(env, true), secret)
    end

    def self.base64digest(data,secret)
      digest = OpenSSL::Digest::Digest.new('sha256')
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
        unless hmac == signature(env, secret) || hmac == signature_legacy(env, secret)
          raise HmacAuthFail, "signature mismatch. Calculated canonical_string: #{canonical_string(env).inspect}"
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

    def self.generated_md5(env, legacy = false)
      env["rack.input"].rewind
      request_body = env["rack.input"].read
      env["rack.input"].rewind
      if legacy
        OpenSSL::Digest::SHA256.hexdigest(request_body)
      else
        request_body.empty? ? nil : OpenSSL::Digest::SHA256.hexdigest(request_body)
      end
    end

  end
end
