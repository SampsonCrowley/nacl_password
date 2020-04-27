require_relative 'boot'

require 'rails/all'
require 'coerce_boolean'
Warning[:deprecated] = CoerceBoolean.from(ENV['ENABLE_RUBY_DEPRECATED'], strict: true)
Warning[:experimental] = CoerceBoolean.from(ENV['ENABLE_RUBY_EXPERIMENTAL'], strict: true)

Bundler.require(*Rails.groups)
require "nacl_password"

module Dummy
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 6.0

    # Settings in config/environments/* take precedence over those specified here.
    # Application configuration can go into files in config/initializers
    # -- all .rb files in that directory are automatically loaded after loading
    # the framework and any gems in your application.
  end
end
