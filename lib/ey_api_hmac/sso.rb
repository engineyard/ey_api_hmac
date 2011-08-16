module EY
  module ApiHMAC
    module SSO

      def self.sign(url, parameters, auth_id, auth_key)
        uri = URI.parse(url)
        raise ArgumentError, "use parameters argument, got query: '#{uri.query}'" if uri.query
        uri.query = parameters.sort.map {|e| e.map{|str| CGI.escape(str.to_s)}.join '='}.join '&'
        signature = CGI.escape(ApiHMAC.base64digest(uri.query.to_s, auth_key))
        uri.query += "&signature=#{signature}"
        uri.to_s
      end

      def self.authenticated?(url, auth_id, auth_key)
        uri = URI.parse(url)
        signature = CGI.unescape(uri.query.match(/&signature=(.*)$/)[1])
        signed_string = uri.query.gsub(/&signature=(.*)$/,"")
        ApiHMAC.base64digest(signed_string.to_s, auth_key) == signature
      end

    end
  end
end