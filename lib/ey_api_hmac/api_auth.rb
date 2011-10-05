module EY
  module ApiHMAC
    module ApiAuth

      # Server middleware to validate requests, setup with a block that returns the auth_key given an auth_id
      #
      # To pass authentication information through to your app, be sure to set something in env.
      # Look at EY::ApiHMAC::ApiAuth::Server for an example
      #
      # raise EY::ApiHMAC::HmacAuthFail, "your message" to fail authentication.
      class LookupServer
        def initialize(app, &lookup)
          @app, @lookup = app, lookup
        end

        def call(env)
          begin
            ApiHMAC.authenticate!(env) do |auth_id|
              @lookup.call(env, auth_id)
            end
          rescue HmacAuthFail => e
            return [401, {}, ["Authentication failure: #{e.message}"]]
          end
          @app.call(env)
        end
      end

      # Consumer id is set to this env key when using EY::ApiHMAC::ApiAuth::Server
      CONSUMER = "ey_api_hmac.consumer_id"

      # Server middleware to validate requests
      #
      # Initialize with a class that responds_to :find_by_auth_id, :id, :auth_key
      #
      # Sets env['ey_api_hmac.consumer_id'] to the id of the object returned by class.find_by_auth_id(auth_id)
      class Server < LookupServer
        def initialize(app, klass)
          unless klass.respond_to?(:find_by_auth_id)
            raise ArgumentError, "EY::ApiHMAC::ApiAuth::Server class must respond to find_by_auth_id"
          end

          lookup = Proc.new do |env, auth_id|
            if consumer = klass.find_by_auth_id(auth_id)
              env[CONSUMER] = consumer.id
              consumer.auth_key
            else
              raise HmacAuthFail
            end
          end

          super(app, &lookup)
        end
      end

      # Client middleware that's used to add authentication to requests.
      class Client
        class AuthFailure < RuntimeError
        end

        def initialize(app, auth_id, auth_key)
          @app, @auth_id, @auth_key = app, auth_id, auth_key
        end
        def call(env)
          ApiHMAC.sign!(env, @auth_id, @auth_key)
          tuple = @app.call(env)
          if tuple.first.to_i == 401
            raise AuthFailure, "HMAC Authentication Failed: #{tuple.last}"
          end
          tuple
        end
      end

    end
  end
end
