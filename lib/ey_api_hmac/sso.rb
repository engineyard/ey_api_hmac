module EY
  module ApiHMAC
    module SSO

      def self.sign(url, parameters, auth_id, auth_key)
        uri = URI.parse(url)
        if uri.query
          extra_params = CGI.parse(uri.query)
          verify_params!(url, extra_params, parameters)
          parameters.merge!(extra_params)
        end
        uri.query = params_to_string(parameters)
        signature = CGI.escape(signature_param(uri.to_s, auth_id, auth_key))
        uri.query += "&signature=#{signature}"
        uri.to_s
      end

      def self.authenticate!(url, &lookup)
        uri = URI.parse(url)
        unless uri.query
          raise HmacAuthFail, "Url has no query"
        end
        parameters = CGI.parse(uri.query)
        signature = parameters["signature"]
        unless signature
          raise HmacAuthFail, "Url has no signature"
        end
        return false unless signature
        signature = signature.first
        if md = Regexp.new("AuthHMAC ([^:]+):(.+)$").match(signature)
          access_key_id = md[1]
          hmac = md[2]
          secret = lookup.call(access_key_id)
          unless authenticated?(url, access_key_id, secret)
            raise HmacAuthFail, "Authentication failed for #{access_key_id}"
          end
          access_key_id
        else
          raise HmacAuthFail, "Incorrect signature"
        end
      end

      def self.authenticated?(url, auth_id, auth_key)
        uri = URI.parse(url)
        return false unless uri.query
        query_params = CGI.parse(uri.query)
        signature = arr_to_string(query_params.delete("signature"))
        uri.query = params_to_string(query_params)
        expected = signature_param(uri.to_s, auth_id, auth_key)
        signature == expected
      end

      def self.signature_param(signed_string, auth_id, auth_key)
        ApiHMAC.auth_string(auth_id, ApiHMAC.base64digest(signed_string, auth_key))
      end

      private

      def self.arr_to_string(arr)
        if arr.respond_to?(:join)
          arr = arr.join("")
        end
        arr.to_s
      end

      def self.params_to_string(parameters)
        result = parameters.sort_by(&:to_s).map do |e|
          e.map do |str| 
            CGI.escape(arr_to_string(str))
          end.join '='
        end.join '&'
        result
      end

      def self.verify_params!(url, extra_params, parameters)
        illegal_query_params = parameters.keys.map(&:to_s) + ["signature"]
        extra_params.keys.each do |k|
          raise ArgumentError, "Got illegal paramter: '#{k}' in '#{url}'" if illegal_query_params.include?(k.to_s)
        end
      end

    end
  end
end