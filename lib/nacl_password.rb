# encoding: utf-8
# frozen_string_literal: true

require 'coerce_boolean'

module NaClPassword
  INVALID_OPTION_MESSAGE = "predefined options are :min, :interactive, :moderate, :sensitive, and :max"
  UNCOERCEABLE_OPTION_MESSAGE = "value must be coercable to an integer or one of the predefined options (:min | :interactive | :moderate | :sensitive | :max)"

  # Load rbnacl gem only when nacl_password is used. This is to avoid
  # the entire app using this gem being dependent on a binary library.
  def self.load_gem
    require "rbnacl"
  rescue LoadError, NameError
    $stderr.puts <<-ERROR
      You don't have rbnacl installed in your application.
      Please add it to your Gemfile and run bundle install
    ERROR

    raise
  end

  # The Argon2 hash function can handle maximum 2^32 bytes, but system available
  # memory probably cannot.
  # A password of length 1024 bytes is way more than any user would ever need.
  # Put a restriction on password length that keeps memory usage in the available
  # range, but is more than anyone would ever need.
  # other defaults are tested ranges of functional values for libsodium that
  # allow maximum possible security without crashing the system
  def self.setup
    load_gem
    ::NaClPassword::Argon2              ||= RbNaCl::PasswordHash::Argon2
    ::NaClPassword::MAX_PASSWORD_LENGTH ||= 1024
    ::NaClPassword::OPS_LIMIT_RANGE     ||= 3..20
    ::NaClPassword::MEM_LIMIT_RANGE     ||= (2**25)..(2**32) #32 MB - 4 GB
    ::NaClPassword::DIGEST_SIZE_RANGE   ||= 64..512
    self
  end

  def self.const_missing(name)
    NaClPassword.setup
    if const_defined?(name)
      const_get(name)
    else
      super
    end
  end

  class << self
    attr_reader :ops_limit # :nodoc:
    attr_reader :mem_limit # :nodoc:
    attr_reader :digest_size # :nodoc:

    def ops_limit=(value)
      @ops_limit = get_ops_limit(value)
    end

    def mem_limit=(value)
      @mem_limit = get_mem_limit(value)
    end

    def digest_size=(value)
      @digest_size = get_digest_size(value)
      digest_size
    end

    def generate(password)
      salt = RbNaCl::Random.random_bytes(Argon2::SALTBYTES)
      ops = get_ops_limit
      mem = get_mem_limit
      size = get_digest_size
      "#{
        Base64.strict_encode64(encrypt(password, salt, ops, mem, size))
      }.#{
        Base64.strict_encode64(salt)
      }.#{
        ops
      }.#{
        mem
      }.#{
        size
      }"
    end

    def authenticate(encoded, password)
      digest, *metadata = decode(encoded)
      RbNaCl::PasswordHash.argon2id(password, *metadata) == digest
    end

    def self.const_missing(name)
      NaClPassword.const_missing(name)
    end

    private
      def encrypt(...)
        RbNaCl::PasswordHash.argon2id(...)
      end

      def decode(encoded)
        digest_64, salt_64, ops, mem, size = encoded.split(".")
        digest = Base64.strict_decode64(digest_64)
        salt = Base64.strict_decode64(salt_64)
        ops  = get_ops_limit(ops)
        mem  = get_mem_limit(mem)
        size = get_digest_size(size)
        [ digest, salt, ops, mem, size ]
      end

      def get_ops_limit(ops = NaClPassword.ops_limit)
        ops = :moderate unless CoerceBoolean.from(ops)

        case ops
        when :min         then OPS_LIMIT_RANGE.min
        when :interactive then 5
        when :moderate    then 10
        when :sensitive   then 15
        when :max         then OPS_LIMIT_RANGE.max
        when Symbol
          raise ArgumentError, INVALID_OPTION_MESSAGE
        else
          case ops = ops.to_i
          when OPS_LIMIT_RANGE then ops
          else
            raise \
              ArgumentError,
              "ops_limit must be within the range #{OPS_LIMIT_RANGE}"
          end
        end
      rescue NoMethodError
        raise ArgumentError, UNCOERCEABLE_OPTION_MESSAGE
      end

      def get_mem_limit(mem = NaClPassword.mem_limit)
        mem = :moderate unless CoerceBoolean.from(mem)

        case mem
        when :min         then MEM_LIMIT_RANGE.min # 32mb
        when :interactive then (2**26)             # 64mb
        when :moderate    then (2**28)             # 256mb
        when :sensitive   then (2**30)             # 1024mb
        when :max         then MEM_LIMIT_RANGE.max # 4096mb
        when Symbol
          raise ArgumentError, INVALID_OPTION_MESSAGE
        else
          case mem = mem.to_i
          when MEM_LIMIT_RANGE then mem
          else
            raise \
              ArgumentError,
              "mem_limit must be within the range #{MEM_LIMIT_RANGE}"
          end
        end
      rescue NoMethodError
        raise ArgumentError, UNCOERCEABLE_OPTION_MESSAGE
      end

      def get_digest_size(size = NaClPassword.digest_size)
        size = :moderate unless CoerceBoolean.from(size)

        case size
        when :min         then DIGEST_SIZE_RANGE.min
        when :interactive then DIGEST_SIZE_RANGE.min * 2
        when :moderate    then DIGEST_SIZE_RANGE.min * 4
        when :sensitive   then DIGEST_SIZE_RANGE.min * 8
        when :max         then DIGEST_SIZE_RANGE.max
        when Symbol
          raise ArgumentError, INVALID_OPTION_MESSAGE
        else
          case size = size.to_i
          when DIGEST_SIZE_RANGE
            unless size % 64 == 0
              raise ArgumentError, "digest_size must be a multiple of 64"
            end

            size
          else
            raise ArgumentError, "digest_size must be within the range #{DIGEST_SIZE_RANGE}"
          end
        end
      rescue NoMethodError
        raise ArgumentError, UNCOERCEABLE_OPTION_MESSAGE
      end
  end

  self.ops_limit   = :moderate
  self.mem_limit   = :moderate
  self.digest_size = :moderate
end

require "nacl_password/railtie" if defined? Rails
