require "spec_helper"
require 'ey_api_hmac'

describe EY::ApiHMAC::BaseConnection do
  before do
    @connection = EY::ApiHMAC::BaseConnection.new("123", "456")
  end
  describe "handle_error" do
    describe "on 500" do
      before do
        @connection.backend = lambda do |env|
          ["500", {}, [""]]
        end
      end
      it "raises an error" do
        lambda { @connection.post("/", "blah") }.should raise_exception(EY::ApiHMAC::BaseConnection::UnknownError)
      end
      it "calls the error handler if one is registered" do
        errors = []
        @connection.handle_errors_with{|*args| errors << [args]; "handled"}
        @connection.post("/", "blah").should eq("handled")
      end
    end
    describe "on bad body" do
      it "calls the error handler" do
        @connection.backend = lambda do |env|
          ["200", {"Content-Type" => "application/json"}, ["200 OK"]]
        end
        errors = []
        @connection.handle_errors_with{|*args| errors << args; false}
        lambda { @connection.post("/", "blah") {} }.should raise_exception(JSON::ParserError)
        errors.should_not be_empty
        request, response, exception = *errors.first
        request[:url].should eq("/")
        request[:body].should eq("blah")
        request[:method].should eq :post
        request[:headers]["Accept"].should eq "application/json"
        response[:status].should eq 200
        response[:body].should eq("200 OK")
        response[:headers].should eq({"Content-Type" => "application/json"})
      end
    end
  end
end
