require 'ey_api_hmac'
require 'cgi'


describe EY::ApiHMAC do

  describe "SSO" do
    before do
      @url = 'http://example.com/sign_test'
      @parameters = {
        "foo" => "bar",
        "zarg" => "boot",
        "xargs" => 5
      }
      @auth_id = "3243afed3242"
      @auth_key = "987a87c98f78d9a8c798f7d89"
    end

    it "can sign sso calls" do
      signed_url = EY::ApiHMAC::SSO.sign(@url, @parameters, @auth_id, @auth_key)
      uri = URI.parse(signed_url)

      uri.scheme.should eq 'http'
      uri.host.should eq 'example.com'
      uri.path.should eq '/sign_test'

      parameters = CGI::parse(uri.query)
      parameters["signature"].first.should eq EY::ApiHMAC::SSO.signature_param(
        "http://example.com/sign_test?foo=bar&xargs=5&zarg=boot", @auth_id, @auth_key)
    end

    it "can verify signed requests" do
      signed_url = EY::ApiHMAC::SSO.sign(@url, @parameters, @auth_id, @auth_key)
      EY::ApiHMAC::SSO.authenticated?(signed_url,  @auth_id, @auth_key).should be_true
      EY::ApiHMAC::SSO.authenticated?(signed_url + 'a',  @auth_id, @auth_key).should be_false
    end

    describe "extracting auth_id and validating in the same call" do
      before do
        @auth_key_lookup = Proc.new do |auth_id|
          (auth_id == @auth_id) && @auth_key
        end
      end
      it "works" do
        signed_url = EY::ApiHMAC::SSO.sign(@url, @parameters, @auth_id, @auth_key)
        EY::ApiHMAC::SSO.authenticate!(signed_url, &@auth_key_lookup).should eq @auth_id
      end

      it "unauthorized when url is tainted" do
        signed_url = EY::ApiHMAC::SSO.sign(@url, @parameters, @auth_id, @auth_key)
        signed_url.gsub!("bar","baz")
        lambda{
          EY::ApiHMAC::SSO.authenticate!(signed_url, &@auth_key_lookup).should be_false
        }.should raise_error(EY::ApiHMAC::HmacAuthFail)
      end

      it "unauthorized when lookup fails" do
        lambda{
          EY::ApiHMAC::SSO.authenticate!("http://example.com/sign_test"){|x| false}
        }.should raise_error(EY::ApiHMAC::HmacAuthFail)
      end

      it "unauthorized with crappy urls" do
        lambda{
          EY::ApiHMAC::SSO.authenticate!("http://example.com/sign_test", &@auth_key_lookup)
        }.should raise_error(EY::ApiHMAC::HmacAuthFail)
        lambda{
          EY::ApiHMAC::SSO.authenticate!("http://example.com/sign_test?foo=bar", &@auth_key_lookup)
        }.should raise_error(EY::ApiHMAC::HmacAuthFail)
        lambda{
          EY::ApiHMAC::SSO.authenticate!("http://example.com/sign_test?signature=baz", &@auth_key_lookup)
        }.should raise_error(EY::ApiHMAC::HmacAuthFail)
      end

    end

    it "can verify requests with no query as invalid" do
      EY::ApiHMAC::SSO.authenticated?("http://example.com/sign_test",  @auth_id, @auth_key).should be_false
    end

    it "catches changes to the url" do
      signed_url = EY::ApiHMAC::SSO.sign(@url, @parameters, @auth_id, @auth_key)
      EY::ApiHMAC::SSO.authenticated?(signed_url,  @auth_id, @auth_key).should be_true
      tampered_url = signed_url.gsub("sign_test", "admin")
      EY::ApiHMAC::SSO.authenticated?(tampered_url,  @auth_id, @auth_key).should be_false
    end

    it "catches changes to the parameters" do
      signed_url = EY::ApiHMAC::SSO.sign(@url, @parameters, @auth_id, @auth_key)
      EY::ApiHMAC::SSO.authenticated?(signed_url,  @auth_id, @auth_key).should be_true
      tampered_url = signed_url.gsub("foo", "fool")
      EY::ApiHMAC::SSO.authenticated?(tampered_url,  @auth_id, @auth_key).should be_false
    end

    it "can sign and verify urls with parameters" do
      url_with_params = "http://example.com/sign_test?baz=bert&stuff=awesome"
      signed_url = EY::ApiHMAC::SSO.sign(url_with_params, @parameters, @auth_id, @auth_key)
      EY::ApiHMAC::SSO.authenticated?(signed_url,  @auth_id, @auth_key).should be_true
    end

    it "raises when the same parameter appears both in query and in arg" do
      url = "http://example.com/sign_test?foo=bar"
      lambda{
        EY::ApiHMAC::SSO.sign(url, @parameters, @auth_id, @auth_key)
      }.should raise_error(/foo/)
    end

    it "verifies this random real-world use case" do
      auth_id = "676f8731f9d3bfd0"
      auth_key = "b7c65a18f6955d58f06a439fb881d1565c17e840999500f2aed6859144de5bac4d1a670119c9b7a9"

      url = "http://ec2-107-22-254-37.compute-1.amazonaws.com/eyintegration/sso/customers/1?access_level=owner&ey_return_to_url=https%3A%2F%2Fcloud.engineyard.com%2Faccounts%2F10398%2Fservices&ey_user_id=10133&ey_user_name=Jacob+Chronatog-Demo+Burkhart&timestamp=2011-10-07T23%3A15%3A50%2B00%3A00&signature=AuthHMAC+676f8731f9d3bfd0%3AnvsCICd%2F00dvFCpJYfvI9LTl81s%3D"

      EY::ApiHMAC::SSO.authenticated?(url, auth_id, auth_key).should be_true
    end

    #TODO: write a test that fails if we skip the CGI.unescape

    #TODO: provide signature methods

    #TODO: test that you get an error when you try to sign a url with any of the "Reserved" parameters (signature or timestamp)

    #TODO: Rename "signature" to "ey_api_sso_hmac_signature"

    #TODO: provide a timestamp? maybe an expiry time would be better

    #TODO: should the other params be part of the gem?
      # ey_user_id – the unique identifier for the user.
      # ey_user_name – the full name of the user in plain text. Example: “John Doe”.
      # access_level – either “owner” or “collaborator”.
      # ey_return_to_url – the url to be used when sending the user back to EY.
      # timestamp – time the signature was calculated, URL should be considered invalid is timestamp is more than 5 minutes off.
      # signature_method – hash method used to generate the signature
      # signature – HMAC digest of the other parameters and url (using the API secret)

  end
end
