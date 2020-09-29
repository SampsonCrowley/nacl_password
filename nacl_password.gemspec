$:.push File.expand_path("lib", __dir__)

# Maintain your gem's version:
require "nacl_password/version"

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = "nacl_password"
  s.version     = NaClPassword::VERSION
  s.license     = "MIT"
  s.authors     = ["Sampson Crowley"]
  s.email       = ["sampsonsprojects@gmail.com"]
  s.homepage    = "https://github.com/SampsonCrowley/nacl_password"
  s.summary     = "RbNaCl on Rails"
  s.description = <<-TEXT
    Easier encryption and decryption with libsodium while remaining configurable
    with validated options. Also includes a concern for a "has_secure_password"
    style one-line setup
  TEXT

  s.files = Dir["lib/**/*", "MIT-LICENSE", "README.md"]

  s.add_dependency "coerce_boolean", "~> 0.1"
  s.add_dependency "rbnacl", "~> 7.1"

  s.add_development_dependency "rails", "~> 6.0", ">= 6.0.3.3"
  s.add_development_dependency "sqlite3"
end
