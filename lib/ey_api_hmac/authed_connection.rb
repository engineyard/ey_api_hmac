require 'ey_api_hmac/base_connection'

module EY
  module ApiHMAC
    class AuthedConnection < BaseConnection
      attr_reader :auth_id, :auth_key

      def initialize(auth_id, auth_key, user_agent = nil)
        @auth_id = auth_id
        @auth_key = auth_key
        super(user_agent)
      end

    protected

      def client
        bak = self.backend
        #damn you scope!
        auth_id_arg = auth_id
        auth_key_arg = auth_key
        @client ||= Rack::Client.new do
          use EY::ApiHMAC::ApiAuth::Client, auth_id_arg, auth_key_arg
          run bak
        end
      end

    end
  end
end
