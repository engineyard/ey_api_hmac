require 'ey_api_hmac/base_connection'

module EY
  module ApiHMAC
    class AuthedConnection < BaseConnection
      attr_reader :auth_id, :auth_key

      def initialize(auth_id, auth_key, user_agent = nil)
        @auth_id = auth_id
        @auth_key = auth_key
        super(user_agent)
        self.middlewares.unshift [EY::ApiHMAC::ApiAuth::Client, auth_id, auth_key]
      end

    end
  end
end
