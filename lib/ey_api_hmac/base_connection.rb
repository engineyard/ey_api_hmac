require 'rack/client'
require 'rack-idempotent'
require 'json'
require 'time'

module EY
  module ApiHMAC
    class BaseConnection

      attr_accessor :middlewares

      def initialize(user_agent = nil)
        @standard_headers = {
          'Accept' => 'application/json',
          'HTTP_DATE' => Time.now.httpdate,
          'USER_AGENT' => user_agent || default_user_agent
        }
        self.middlewares = [Rack::Idempotent]
      end

      def default_user_agent
        "ApiHMAC"
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
        attr_reader :response

        def initialize(response)
          @response = response
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

      def handle_errors_with(&error_handler)
        @error_handler = error_handler
      end

    protected

      def client
        #damn you scope!
        backend = self.backend
        middlewares = self.middlewares
        @client ||= Rack::Client.new do
          middlewares.each do |middleware|
            use *Array(middleware)
          end
          run backend
        end
      end

      def request(method, url, body = nil, &block)
        response = nil
        request_headers = @standard_headers.dup
        if body
          body_json = body.to_json
          request_headers["CONTENT_LENGTH"] = body_json.size.to_s
          request_headers["CONTENT_TYPE"] = 'application/json'
          response = client.send(method, url, request_headers, body_json)
        else
          response = client.send(method, url, request_headers)
        end
        class << response
          def json
            JSON.parse(self.body)
          end
        end
        handle_response(url, response, &block)
      rescue => e
        request_hash = {:method => method, :url => url, :headers => request_headers, :body => body}
        response_hash = {:status => response.status, :body => response.body, :headers => response.headers} if response
        handle_error(request_hash, (response_hash || {}), e) || (raise e)
      end

      def handle_error(request, response, exception)
        if @error_handler
          @error_handler.call(request, response, exception)
        end
      end

      def handle_response(url, response)
        case response.status
        when 200, 201
          if block_given?
            yield response.json, response["Location"]
          else
            response
          end
        when 204
          if block_given?
            yield({}, response["Location"])
          else
            response
          end
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
