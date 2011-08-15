require 'ey_api_hmac'
require 'auth-hmac'

describe EY::ApiHMAC::ApiAuth do

  #TODO: reject requests with old dates?

  describe "AuthHMAC working" do

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
      EY::ApiHMAC.sign!(env, 'my-key-id', 'secret', true)
    }.should raise_error(/'HTTP_DATE' header missing and required/)
  end

end