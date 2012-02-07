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
    use Rack::Config do |env|
      env['HTTP_DATE'] = Time.now.httpdate
    end
    use EY::ApiHMAC::ApiAuth::Client, auth_id_arg, auth_key_arg
    run Rack::Client::Handler::NetHTTP
  end
```

this will add the correct Authorization header to all requests made with this rack-client.

# Imlementation details:

before signed:

    {"REQUEST_URI"=>"http://example.com/api/1/service_accounts/1324/messages", "PATH_INFO"=>"/api/1/service_accounts/1324/messages", "CONTENT_TYPE"=>"application/json", "HTTP_ACCEPT"=>"application/json", "REQUEST_METHOD"=>"POST", "HTTP_DATE"=>"Thu, 15 Dec 2011 23:50:33 GMT", "rack.input"=>#<StringIO:0x007fd9239f6998>}

request body:

    {"message":{"message_type":"status","subject":"Everything looks good.","body":null}}

auth_id:

    123bc211233eabc

auth_key:

    abc474e3fc9bddf6d41236b70cc5a952f3681166e1239214740d13eecd12318f7b8d27123b61eabc

canonical_string:

    "POST\napplication/json\ne8fa80541e3726e2cf4c71d07a7bd9fd\nThu, 15 Dec 2011 23:50:33 GMT\n/api/1/service_accounts/1324/messages"

signature:

    UZDkXszu4dp6Gz2TEGcy/cVt0R0=

now signed:

    {"REQUEST_URI"=>"http://example.com/api/1/service_accounts/1324/messages", "PATH_INFO"=>"/api/1/service_accounts/1324/messages", "CONTENT_TYPE"=>"application/json", "HTTP_ACCEPT"=>"application/json", "REQUEST_METHOD"=>"POST", "HTTP_DATE"=>"Thu, 15 Dec 2011 23:50:33 GMT", "rack.input"=>#<StringIO:0x007fd9239f6998>, "HTTP_AUTHORIZATION"=>"AuthHMAC 123bc211233eabc:UZDkXszu4dp6Gz2TEGcy/cVt0R0="}

## Requests with empty request body.

In prior versions (0.1.x), we expected the MD5 hash of an empty string (d41d8cd98f00b204e9800998ecf8427e) to be used in the canonical string when the HTTP request had no body.  In the latest version (0.4.x), we expect an empty string to used instead.  We've made the "server" component of ey_api_hmac verify and accept both styles of canonical string, however there is no backwards-compatible solution for the client, so we always use empty string when the content body is empty.

This change was made to be compatible with the other HMAC already in use internally at Engine Yard: http://rubygems.org/gems/auth-hmac.
