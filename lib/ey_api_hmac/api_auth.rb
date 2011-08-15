module EY
  module ApiHMAC
    module ApiAuth
      CONSUMER = "ey_api_hmac.consumer_id"

      #a Server middleware to validate requests, setup with a block to lookup the auth_key based on auth_id
      class LookupServer
        def initialize(app, &lookup)
          @app, @lookup = app, lookup
        end

        #TODO: rescue HmacAuthFail and return 403?
        def call(env)
          ApiHMAC.authenticate!(env) do |auth_id|
            @lookup.call(env, auth_id)
          end
          @app.call(env)
        end
      end

      #a Server middleware to validate requests, setup with a class that responds_to :find_by_auth_id, :id, :auth_key
      class Server < LookupServer
        def initialize(app, klass)
          lookup = Proc.new do |env, auth_id|
            if consumer = klass.find_by_auth_id(auth_id)
              env[CONSUMER] = consumer.id
              consumer.auth_key
            else
              raise "no #{klass} consumer #{auth_id.inspect}"
            end
          end
          super(app, &lookup)
        end
      end

      #the Client middleware that's used to add authentication to requests
      class Client
        def initialize(app, auth_id, auth_key)
          @app, @auth_id, @auth_key = app, auth_id, auth_key
        end
        def call(env)
          ApiHMAC.sign!(env, @auth_id, @auth_key)
          @app.call(env)
        end
      end

    end
  end
end