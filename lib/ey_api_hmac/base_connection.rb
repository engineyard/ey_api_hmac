require 'rack/client'
require 'json'
require 'time'

module EY
  module ApiHMAC
    class BaseConnection
      attr_reader :auth_id, :auth_key

      def initialize(auth_id, auth_key, user_agent = nil)
        @auth_id = auth_id
        @auth_key = auth_key
        @standard_headers = {
            'CONTENT_TYPE' => 'application/json',
            'Accept' => 'application/json',
            'Date' => Time.now.httpdate,
            'USER_AGENT' => user_agent || default_user_agent
        }
      end

      class NotFound < StandardError
        def initialize(url)
          super("#{url} not found")
        end
      end

      class ValidationError < StandardError
        attr_reader :error_messages

        def initialize(response)
          json_response = JSON.parse(response.body)
          @error_messages = json_response["error_messages"]
          super("error: #{@error_messages.join("\n")}")
        rescue => e
          @error_messages = []
          super("error: #{response.body}")
        end
      end

      class UnknownError < StandardError
        def initialize(response)
          super("unknown error(#{response.status}): #{response.body}")
        end
      end

      attr_writer :backend
      def backend
        @backend ||= Rack::Client::Handler::NetHTTP
      end

      def post(url, body, &block)
        request(:post, url, body, &block)
      end

      def put(url, body, &block)
        request(:put, url, body, &block)
      end

      def delete(url, &block)
        request(:delete, url, &block)
      end

      def get(url, &block)
        request(:get, url, &block)
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

      def request(method, url, body = nil, &block)
        if body
          response = client.send(method, url, @standard_headers, body.to_json)
        else
          response = client.send(method, url, @standard_headers)
        end
        handle_response(url, response, &block)
      end

      def handle_response(url, response)
        case response.status
        when 200, 201
          json_body = JSON.parse(response.body)
          yield json_body, response["Location"] if block_given?
        when 404
          raise NotFound.new(url)
        when 400
          raise ValidationError.new(response)
        else
          raise UnknownError.new(response)
        end
      end
    end
  end
end
