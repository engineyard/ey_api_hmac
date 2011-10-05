require 'spec_helper'

require 'ey_api_hmac'
require 'auth-hmac'
require 'rack/contrib'
require 'time'

describe EY::ApiHMAC::ApiAuth do

  #TODO: reject requests with old dates?

  describe "AuthHMAC working" do

    it "works for documented/realistic example" do
      req_body = %q{{"message":{"message_type":"status","subject":"Everything looks good.","body":null}}}
      env = {'PATH_INFO' => "/api/1/service_accounts/1324/messages",
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'REQUEST_METHOD' => "POST",
        'HTTP_DATE' => Time.now.httpdate,
        "rack.input" => StringIO.new(req_body)}

      puts "before signed: \n#{env.inspect}\n\n"
      puts "request body: \n#{req_body}\n\n"

      auth_id = "123bc211233eabc"
      auth_key = "abc474e3fc9bddf6d41236b70cc5a952f3681166e1239214740d13eecd12318f7b8d27123b61eabc"

      puts "auth_id: #{auth_id}"
      puts "auth_key: #{auth_key}\n\n"

      canonical_string = EY::ApiHMAC.canonical_string(env)
      puts "canonical_string: \n#{canonical_string.inspect}\n\n"

      signature = EY::ApiHMAC.signature(env, auth_key)
      puts "signature: \n#{signature}\n\n"

      EY::ApiHMAC.sign!(env, auth_id, auth_key)
      puts "now signed: \n#{env.inspect}\n\n"

      lookup = Proc.new{ |key| auth_key if key == auth_id }

      EY::ApiHMAC.authenticated?(env, &lookup).should be_true
    end

    before(:each) do
      @env = {'PATH_INFO' => "/path/to/put",
        'QUERY_STRING' => 'foo=bar&bar=foo',
        'CONTENT_TYPE' => 'text/plain',
        'HTTP_CONTENT_MD5' => 'blahblah',
        'REQUEST_METHOD' => "PUT",
        'HTTP_DATE' => "Thu, 10 Jul 2008 03:29:56 GMT",
        "rack.input" => StringIO.new}
      @request = Rack::Request.new(@env)
    end

    describe ".canonical_string" do
      it "should generate a canonical string using default method" do
        expected = "PUT\ntext/plain\nblahblah\nThu, 10 Jul 2008 03:29:56 GMT\n/path/to/put"
        AuthHMAC.canonical_string(@request).should == expected
        EY::ApiHMAC.canonical_string(@env).should == expected
      end
    end

    describe ".signature" do
      it "should generate a valid signature string for a secret" do
        expected = "71wAJM4IIu/3o6lcqx/tw7XnAJs="
        AuthHMAC.signature(@request, 'secret').should == expected
        EY::ApiHMAC.signature(@env, 'secret').should == expected
      end
    end

    describe "sign!" do
      before do
        @expected = "AuthHMAC my-key-id:71wAJM4IIu/3o6lcqx/tw7XnAJs="
      end

      it "signs as expected with AuthHMAC" do
        AuthHMAC.sign!(@request, "my-key-id", "secret")
        @request['Authorization'].should == @expected
      end

      it "signs as expected with ApiAuth" do
        EY::ApiHMAC.sign!(@env, 'my-key-id', 'secret')
        @env["HTTP_AUTHORIZATION"].should == @expected
      end

    end

    describe "authenticated?" do
      describe "request signed by AuthHMAC" do
        before do
          AuthHMAC.sign!(@request, 'access key 1', 'secret')
          @env["HTTP_AUTHORIZATION"] = @request["Authorization"]
        end

        it "verifies by ApiAuth" do
          @lookup = Proc.new{ |key| 'secret' if key == 'access key 1' }
          EY::ApiHMAC.authenticated?(@env, &@lookup).should be_true
        end

        it "verifies by AuthHMAC" do
          @authhmac = AuthHMAC.new({"access key 1" => 'secret'})
          @authhmac.authenticated?(@request).should be_true
        end
      end
      describe "request signed by ApiAuth" do
        before do
          EY::ApiHMAC.sign!(@env, 'access key 1', 'secret')
        end

        it "verifies by ApiAuth" do
          @lookup = Proc.new{ |key| 'secret' if key == 'access key 1' }
          EY::ApiHMAC.authenticated?(@env, &@lookup).should be_true
        end

        it "verifies by AuthHMAC" do
          @authhmac = AuthHMAC.new({"access key 1" => 'secret'})
          @authhmac.authenticated?(@request).should be_true
        end
      end
    end

    describe "middleware behavior" do
      MockApp = lambda do |is_found, auth_key|
        Rack::Builder.new do
          use EY::ApiHMAC::ApiAuth::Server, MockAuth.new(is_found, auth_key)
          run lambda { |x| [200, {}, ['Success']] }
        end
      end

      def hmac_client(client_auth_key, app)
        client = Rack::Client.new('http://localhost') do
          use Rack::Config do |env|
            env['HTTP_DATE'] = Time.now.httpdate
          end
          use EY::ApiHMAC::ApiAuth::Client, 1, client_auth_key
          run app
        end
      end

      it "responds 401 Unauthorized with no authorization" do
        client = Rack::Client.new('http://localhost') do
          run MockApp.call(true, 'key')
        end

        # no HMAC client means no nice exception for 401s
        response = client.get('/')
        response.status.should == 401
        response.body.should_not == 'Success'
      end

      it "works with correct signing" do
        auth_key = 'key'
        is_found = true

        client = hmac_client(auth_key, MockApp.call(is_found, auth_key))

        response = client.get('/')
        response.status.should == 200
        response.body.should == 'Success'
      end

      it "fails when auth_key isn't correct" do
        auth_id  = 1
        is_found = true

        client = hmac_client('wrongkey', MockApp.call(is_found, 'rightkey'))

        lambda { client.get('/') }.should raise_error(EY::ApiHMAC::ApiAuth::Client::AuthFailure)
      end

      it "fails when no consumer by that auth_id is found" do
        auth_id  = 1
        is_found = false
        auth_key = 'key'

        client = hmac_client(auth_key, MockApp.call(is_found, auth_key))

        lambda { client.get('/') }.should raise_error(EY::ApiHMAC::ApiAuth::Client::AuthFailure)
      end
    end
  end


  describe "without CONTENT_MD5" do
    before do
      @env = {'PATH_INFO' => "/path/to/put",
        'QUERY_STRING' => 'foo=bar&bar=foo',
        'CONTENT_TYPE' => 'text/plain',
        'REQUEST_METHOD' => "PUT",
        'HTTP_DATE' => "Thu, 10 Jul 2008 03:29:56 GMT",
        "rack.input" => StringIO.new("something, something?")}
      @request = Rack::Request.new(@env)
    end

    describe "sign!" do
      before do
        @expected = "AuthHMAC my-key-id:YzKgetuk8Tkz19c4eUqbfg4QrFg="
      end

      it "signs as expected with AuthHMAC" do
       AuthHMAC.sign!(@request, "my-key-id", "secret")
       @request['Authorization'].should == @expected
      end

      it "signs as expected with ApiAuth" do
        EY::ApiHMAC.sign!(@env, 'my-key-id', 'secret')
        @env["HTTP_AUTHORIZATION"].should == @expected
      end

    end
  end

  it "complains when there is no HTTP_DATE" do
    env = {'PATH_INFO' => "/path/to/put",
      'QUERY_STRING' => 'foo=bar&bar=foo',
      'CONTENT_TYPE' => 'text/plain',
      'REQUEST_METHOD' => "PUT",
      "rack.input" => StringIO.new}
    lambda{
      EY::ApiHMAC.sign!(env, 'my-key-id', 'secret')
    }.should raise_error(/'HTTP_DATE' header missing and required/)
  end

end
