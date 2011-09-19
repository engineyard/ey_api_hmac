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
