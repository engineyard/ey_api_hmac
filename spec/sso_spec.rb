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
      signed_url = EY::ApiHMAC.sign_for_sso(@url, @parameters, @auth_id, @auth_key)
      uri = URI.parse(signed_url)

      uri.scheme.should eq 'http'
      uri.host.should eq 'example.com'
      uri.path.should eq '/sign_test'

      parameters = CGI::parse(uri.query)
      parameters["signature"].first.should eq EY::ApiHMAC.base64digest("foo=bar&xargs=5&zarg=boot", @auth_key)
    end

    it "can verify signed requests" do
      signed_url = EY::ApiHMAC.sign_for_sso(@url, @parameters, @auth_id, @auth_key)
      EY::ApiHMAC.verify_for_sso(signed_url,  @auth_id, @auth_key).should be_true
      EY::ApiHMAC.verify_for_sso(signed_url + 'a',  @auth_id, @auth_key).should be_false
    end

    #TODO: write a test that fails if we skip the CGI.unescape

    #TODO: provide signature methods

    #TODO: test that you get an error when you try to sign a url with any of the "Reserved" parameters (signature or timestamp)

    #TODO: send the auth_id in the params too

    #TODO: Rename "signature" to "ey_api_sso_hmac_signature"

    #TODO: provide a time

    #TODO: maybe an expiry time would be better

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