# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "ey_api_hmac/version"

Gem::Specification.new do |s|
  s.name        = "ey_api_hmac"
  s.version     = EY::ApiHMAC::VERSION
  s.authors     = ["Jacob Burkhart & Thorben Schröder & David Calavera & others"]
  s.email       = ["jacob@engineyard.com"]
  s.homepage    = ""
  s.summary     = %q{TODO: Write a gem summary}
  s.description = %q{TODO: Write a gem description}

  s.rubyforge_project = "ey_api_hmac"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'rack-client'
  s.add_development_dependency "rspec"
end
