# encoding: utf-8
# frozen_string_literal: true

require 'test_helper'

class NaClPassword::Test < ActiveSupport::TestCase
  FULL_SUITE = CoerceBoolean.from(ENV["FULL_SUITE"])

  ENCODING_REGEX = %r{
    ((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\.){2}
    ([3-9]|10)\.
    [0-9]+\.
    (64|[1-5][1-9][02468])
  }x

  SPECIAL_CONSTANTS = %i[
    Argon2
    MAX_PASSWORD_LENGTH
    OPS_LIMIT_RANGE
    MEM_LIMIT_RANGE
    DIGEST_SIZE_RANGE
  ].freeze

  PREDEFINED_OPTS = FULL_SUITE ?
    %i[
      min
      interactive
      moderate
      sensitive
      max
    ] :
    %i[
      min
      interactive
      sensitive
    ]

  def does_call_class_method(method_to_stub, **opts, &block)
    does_call_method NaClPassword, method_to_stub, **opts, &block
  end

  test '.setup defines RbNaCl constants' do
    SPECIAL_CONSTANTS.each do |name|
      if NaClPassword.const_defined? name
        NaClPassword.__send__ :remove_const, name
      end
      refute NaClPassword.const_defined? name
    end

    NaClPassword.setup

    SPECIAL_CONSTANTS.each do |name|
      assert NaClPassword.const_defined? name
    end
  end

  test '.const_missing runs setup and returns any dynamic constants if defined' do
    SPECIAL_CONSTANTS.each do |name|
      if NaClPassword.const_defined? name
        NaClPassword.__send__ :remove_const, name
      end

      does_call_class_method(:setup, expected: :skip_input) do
        err = assert_raises(NameError) do
          NaClPassword.const_get name
        end
        assert_equal "uninitialized constant NaClPassword::#{name}", err.message
      end

      refute NaClPassword.const_defined? name
      assert NaClPassword.const_get name
      assert NaClPassword.const_defined? name
    end


    assert_raises(NameError) do
      NaClPassword::RANDOM_CONST
    end
  end

  %w[
    ops_limit
    mem_limit
    digest_size
  ].each do |mthd|
    var = :"@#{mthd}"
    test ".#{mthd} is a getter for @#{mthd}" do
      assert_is_getter NaClPassword, mthd, var
    end

    test ".#{mthd}= parses input and sets @#{mthd} from predefined options (:min, :interactive, :moderate, :sensitive, :max)" do
      symbol_value = original = NaClPassword.instance_variable_get(var)
      PREDEFINED_OPTS.each do |level|
        symbol_value = NaClPassword.__send__("#{mthd}=", level)
        assert_instance_of Integer, symbol_value
        assert_equal NaClPassword.__send__(mthd), symbol_value
      end
      err = assert_raises(ArgumentError) do
        NaClPassword.__send__("#{mthd}=", :other)
      end

      assert_equal \
        "predefined options are :min, :interactive, :moderate, :sensitive, and :max",
        err.message

      assert_equal symbol_value, NaClPassword.__send__(mthd)

      err = assert_raises(ArgumentError) do
        NaClPassword.__send__("#{mthd}=", Object.new)
      end

      assert_equal \
        "value must be coercable to an integer or one of the predefined options (:min | :interactive | :moderate | :sensitive | :max)",
        err.message

      assert_equal symbol_value, NaClPassword.__send__(mthd)

      NaClPassword.instance_variable_set(var, original)
    end

    test ".#{mthd}= sets @#{mthd} to moderate if falsey" do
      original = NaClPassword.instance_variable_get(var)
      NaClPassword.__send__("#{mthd}=", :moderate)
      moderate = NaClPassword.__send__(mthd)

      CoerceBoolean::FALSE_VALUES.each do |val|
        NaClPassword.__send__("#{mthd}=", :max)
        refute_equal moderate, NaClPassword.__send__(mthd)

        NaClPassword.__send__("#{mthd}=", val)

        assert_equal moderate, NaClPassword.__send__(mthd)
      end
      NaClPassword.instance_variable_set(var, original)
    end

    next if mthd == "digest_size"

    next unless FULL_SUITE

    test ".#{mthd}= accepts any number in range of #{mthd.upcase}_RANGE" do
      range = NaClPassword.const_get(:"#{mthd.upcase}_RANGE")
      original = NaClPassword.instance_variable_get(var)

      NaClPassword.__send__("#{mthd}=", nil)
      [
        range.min,
        range.min + 1,
        range.max - 1,
        range.max,
      ].each do |int|
        %i[
          to_i
          to_f
          to_d
          to_s
        ].each do |type|
          NaClPassword.instance_variable_set(var, nil)
          assert_equal int, NaClPassword.__send__("#{mthd}=", int.__send__(type))
          assert_equal int, NaClPassword.__send__("#{mthd}")
        end
      end

      current_value = NaClPassword.__send__("#{mthd}=", :sensitive)

      [
        range.min - 1,
        range.max + 1
      ].each do |int|
        %i[
          to_i
          to_f
          to_d
          to_s
        ].each do |type|
          err = assert_raises(ArgumentError) do
            NaClPassword.__send__("#{mthd}=", int.__send__(type))
          end
          assert_equal current_value, NaClPassword.__send__("#{mthd}")
          assert_match \
            (/^#{mthd} must be within the range [0-9]+\.\.[0-9]+$/),
            err.message
        end
      end

      NaClPassword.instance_variable_set(var, original)
    end
  end

  test '.digest_size= accepts a range between 64 and 512, in multiples of 64' do
    range = NaClPassword::DIGEST_SIZE_RANGE
    original = NaClPassword.instance_variable_get(:@digest_size)

    current_value = original

    range.each do |int|
      %i[
        to_i
        to_f
        to_d
        to_s
      ].each do |type|
        if int % 64 == 0
          NaClPassword.instance_variable_set(:@digest_size, nil)
          NaClPassword.digest_size = int.__send__(type)
          assert_equal int, NaClPassword.digest_size
          current_value = int
        else
          err = assert_raises(ArgumentError) do
            NaClPassword.digest_size = int.__send__(type)
          end
          assert_equal current_value, NaClPassword.digest_size
          assert_equal "digest_size must be a multiple of 64", err.message
        end
      end
    end

    NaClPassword.digest_size = :sensitive
    current_value = NaClPassword.digest_size

    [
      range.min - 1,
      range.max + 1
    ].each do |int|
      %i[
        to_i
        to_f
        to_d
        to_s
      ].each do |type|
        err = assert_raises(ArgumentError) do
          NaClPassword.digest_size = int.__send__(type)
        end
        assert_equal current_value, NaClPassword.digest_size
        assert_equal \
          "digest_size must be within the range #{NaClPassword::DIGEST_SIZE_RANGE}",
          err.message
      end
    end

    NaClPassword.instance_variable_set(:@digest_size, original)
  end

  test '.generate(password) creates an encrypted and encoded hash' do
    assert_match ENCODING_REGEX, string = NaClPassword.generate("password")
  end

  test '.generate(password) encodes the digest and salt in base64' do
    RbNaCl::Random.stub(:random_bytes, "fake_salt") do
      RbNaCl::PasswordHash.stub(:argon2id, "fake_digest") do
        encoded = NaClPassword.generate("password")
        digest64, salt64, *_ = encoded.split(".")
        assert_equal Base64.strict_encode64("fake_digest"), digest64
        assert_equal Base64.strict_encode64("fake_salt"), salt64
      end
    end
  end

  test '.generate(password) encodes the password with the set ops_limit, mem_limit and digest_size' do
    original_ops = NaClPassword.ops_limit
    original_mem = NaClPassword.mem_limit
    original_dig = NaClPassword.digest_size

    PREDEFINED_OPTS.each do |level|
      %w[
        ops_limit
        mem_limit
        digest_size
      ].each do |type|
        NaClPassword.__send__("#{type}=", level)
        encoded = NaClPassword.generate("password")
        _, _, ops, mem, size = encoded.split(".")

        assert_equal NaClPassword.ops_limit, ops.to_i
        assert_equal NaClPassword.mem_limit, mem.to_i
        assert_equal NaClPassword.digest_size, size.to_i
      ensure
        NaClPassword.ops_limit   = original_ops
        NaClPassword.mem_limit   = original_mem
        NaClPassword.digest_size = original_dig
      end
    end
  end
end
