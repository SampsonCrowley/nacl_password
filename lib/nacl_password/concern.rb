# encoding: utf-8
# frozen_string_literal: true

require 'nacl_password'

module NaClPassword
  module Concern
    extend ActiveSupport::Concern

    module ClassMethods
      # Adds methods to set and authenticate against a Argon2 password.
      # This mechanism requires you to have a +XXX_digest+ attribute.
      # Where +XXX+ is the attribute name of your desired password.
      # the +digest+ attribute to use can be set by passing
      # `digest_attribute: non_standard_attribute` to `nacl_password`
      #
      # The following validations are added automatically:
      # * Password must be present on creation
      # * Password length should be less than or equal to 1024 bytes
      # * Confirmation of password (using a +XXX_confirmation+ attribute)
      #
      # If confirmation validation is not needed, simply leave out the
      # value for +XXX_confirmation+ (i.e. don't provide a form field for
      # it). When this attribute has a +nil+ value, the validation will not be
      # triggered.
      #
      # It is also possible to suppress the default validations completely by
      # passing skip_validations: true as an argument.
      #
      # Add rbnacl (~> 7.1) to Gemfile to use #nacl_password:
      #
      #   gem "rbnacl", "~> 7.1"
      #
      # Example:
      #
      #   # Schema: User(name:string, password_digest:string, recovery_password_digest:string)
      #   class User < ActiveRecord::Base
      #     include NaClPassword::Concern
      #     nacl_password
      #     nacl_password :recovery_password, validations: false
      #   end
      #
      #   user = User.new(name: 'david', password: '', password_confirmation: 'nomatch')
      #   user.save                                                  # => false, password required
      #   user.password = 'mUc3m00RsqyRe'
      #   user.save                                                  # => false, confirmation doesn't match
      #   user.password_confirmation = 'mUc3m00RsqyRe'
      #   user.save                                                  # => true
      #   user.recovery_password = "42password"
      #   user.recovery_password_digest                              # => "$2a$04$iOfhwahFymCs5weB3BNH/uXkTG65HR.qpW.bNhEjFP3ftli3o5DQC"
      #   user.save                                                  # => true
      #   user.authenticate('notright')                              # => false
      #   user.authenticate('mUc3m00RsqyRe')                         # => user
      #   user.authenticate_recovery_password('42password')          # => user
      #   User.find_by(name: 'david')&.authenticate('notright')      # => false
      #   User.find_by(name: 'david')&.authenticate('mUc3m00RsqyRe') # => user
      def nacl_password(attribute = :password, digest_attribute: nil, **opts)
        NaClPassword.setup

        digest_attribute ||= "#{attribute}_digest"

        attribute = attribute.to_sym
        digest_attribute = digest_attribute.to_sym

        if digest_attribute.to_s == attribute.to_s
          raise ArgumentError, "Digest Attribute Name can't be the same as Password Attribute Name"
        end

        skip_validations =
          CoerceBoolean.from(opts[:skip_validations]) &&
          (opts[:skip_validations] != :blank)

        length_options =
          skip_validations ? {} :
            { maximum: NaClPassword::MAX_PASSWORD_LENGTH }.
            merge(
              opts[:min_length] == :none \
                ? {} \
                : { minimum: opts[:min_length].presence&.to_i || 8 }
            )


        include InstanceMethodsOnActivation.new(attribute.to_sym, digest_attribute, **length_options)

        unless skip_validations
          include ActiveModel::Validations

          # This ensures the model has a password by checking whether the password_digest
          # is present, so that this works with both new and existing records. However,
          # when there is an error, the message is added to the password attribute instead
          # so that the error message will make sense to the end-user.
          unless opts[:skip_validations] == :blank
            validate do |record|
              unless record.__send__(digest_attribute).present?
                record.errors.add(attribute, :blank)
              end
            end
          end

          validates_length_of attribute, **length_options, allow_blank: true

          validates_confirmation_of attribute, allow_blank: true
        end
      end
    end

    class InstanceMethodsOnActivation < Module
      def initialize(attribute, digest_attribute, **attribute_opts)
        # == Constants ============================================================
        confirmation_var = "@#{attribute}_confirmation"

        # == Attributes ===========================================================
        attr_reader attribute

        define_method("#{attribute}=") do |given_password|
          instance_variable_set("@#{attribute}", given_password.presence)

          if given_password.nil? || given_password.empty?
            self.__send__("#{digest_attribute}=", nil)
          else
            self.__send__(
              "#{digest_attribute}=",
              NaClPassword.generate(given_password)
            )
          end
        end

        define_method("#{attribute}_confirmation=") do |given_password|
          instance_variable_set(confirmation_var, given_password)
        end

        # == Boolean Methods ======================================================
        define_method("#{attribute}_length_valid?") do
          value = self.__send__(attribute)
          invalid = false

          if attribute_opts[:maximum].present?
            invalid ||= (value.length > attribute_opts[:maximum])
          end

          if attribute_opts[:minimum].present?
            invalid ||= (value.length < attribute_opts[:minimum])
          end

          !invalid
        end

        define_method("#{attribute}_confirmed?") do
          self.__send__(attribute) == self.instance_variable_get(confirmation_var)
        end

        define_method("#{attribute}_ready?") do |require_confirmation = false|
          value = self.__send__(attribute)
          if value.nil? || value.empty?
            self.__send__("#{digest_attribute}").present?
          else
            confirmation = self.instance_variable_get(confirmation_var)
            if !require_confirmation && (confirmation.nil? || confirmation.empty?)
              self.__send__("#{attribute}_length_valid?")
            else
              self.__send__("#{attribute}_confirmed?") \
              && self.__send__("#{attribute}_length_valid?")
            end
          end
        end

        # == Instance Methods =====================================================

        # Returns +self+ if the password is correct, otherwise +nil+.
        #
        #   class User < ActiveRecord::Base
        #     nacl_password validations: false
        #   end
        #
        #   user = User.new(name: 'david', password: 'mUc3m00RsqyRe')
        #   user.save
        #   user.authenticate_password('mUc3m00RsqyRe') # => user
        #   user.authenticate_password('notright')      # => nil
        define_method("authenticate_#{attribute}") do |given_password|
          return nil unless attribute_digest = __send__(digest_attribute)
          if NaClPassword.authenticate(attribute_digest, given_password)
            self
          end
        end

        alias_method :authenticate, :authenticate_password if attribute == :password
      end
    end
  end
end
