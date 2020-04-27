module NaClPassword
  class Railtie < ::Rails::Railtie
    initializer 'nacl_password.include_concern' do
      ActiveSupport.on_load(:active_record) do
        require 'nacl_password/concern'
        ActiveRecord::Base.send :include, NaClPassword::Concern
      end
    end
  end
end
