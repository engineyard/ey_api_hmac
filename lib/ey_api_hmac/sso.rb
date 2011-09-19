module EY
  module ApiHMAC
    module SSO

      def self.sign(url, parameters, auth_id, auth_key)
        uri = URI.parse(url)
        if uri.query
          extra_params = CGI.parse(uri.query)
          verify_params!(extra_params, parameters)
          parameters.merge!(extra_params)
        end
        uri.query = parameters.sort_by(&:to_s).map {|e| e.map{|str| CGI.escape(str.to_s)}.join '='}.join '&'
        signature = CGI.escape(signature_param(uri.to_s, auth_id, auth_key))
        uri.query += "&signature=#{signature}"
        uri.to_s
      end

      def self.authenticated?(url, auth_id, auth_key)
        uri = URI.parse(url)
        signature = CGI.unescape(uri.query.match(/&signature=(.*)$/)[1])
        signed_string = uri.to_s.gsub(/&signature=(.*)$/,"")
        signature_param(signed_string.to_s, auth_id, auth_key) == signature
      end

      def self.signature_param(signed_string, auth_id, auth_key)
        ApiHMAC.auth_string(auth_id, ApiHMAC.base64digest(signed_string, auth_key))
      end

      private

      def self.verify_params!(extra_params, parameters)
        illegal_query_params = parameters.keys.map(&:to_s) + ["signature"]
        extra_params.keys.each do |k|
          raise ArgumentError, "Got illegal paramter: '#{k}' in '#{url}'" if illegal_query_params.include?(k.to_s)
        end
      end

    end
  end
end