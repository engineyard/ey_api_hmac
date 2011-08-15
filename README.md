# Engine Yard HMAC api implementation

HMAC basic implementation for Engine Yard services.

# How to use it

Server Rack middleware:

```ruby
  use EY::ApiHMAC::ApiAuth::Server, Consumer
```

Where `Consumer` is a class that responds to find_by_auth_id(auth_id), and returns an object that responds to `id` and `auth_key`.

```ruby
  use EY::ApiHMAC::ApiAuth::LookupServer do |env, auth_id|
    #return the appropriate auth_key here
  end
```

this will validate the Authorization header for all requests and raise on failures

Rack-Client middleware:

```ruby
  client = Rack::Client.new do
    use EY::ApiHMAC::ApiAuth::Client, auth_id_arg, auth_key_arg
    run Rack::Client::Handler::NetHTTP
  end
```

this will add the correct Authorization header to all requests made with this rack-client.
