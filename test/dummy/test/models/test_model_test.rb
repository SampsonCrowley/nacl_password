require 'test_helper'

class TestModelTest < ActiveSupport::TestCase
  def valid_instance
    TestModel.new password: "pass", no_minimum: 'a'
  end

  test "password and no_minimum must be present" do
    instance = TestModel.new
    refute instance.valid?


    assert_equal(
      ["Password can't be blank", "No minimum can't be blank"],
      instance.errors.full_messages
    )

    assert valid_instance.valid?
  end

  test "password must be 4 characters" do
    instance = valid_instance
    instance.password = "a" * 3
    refute instance.valid?
    assert_equal(
      [ "Password is too short (minimum is 4 characters)" ],
      instance.errors.full_messages
    )
  end

  test "test_non_standard must be 8 characters" do
    instance = valid_instance
    instance.test_non_standard = "a" * 7
    refute instance.valid?
    assert_equal(
      [ "Test non standard is too short (minimum is 8 characters)" ],
      instance.errors.full_messages
    )
  end

  test "non_validated and no_minimum can be any length" do
    instance = valid_instance
    instance.non_validated = "a"
    instance.no_minimum = "a"
    assert instance.valid?
  end

  test "password, no_minimum, and test_non_standard require a valid confirmation if given" do
    %w[
      password
      no_minimum
      test_non_standard
    ].each do |attr|
      instance = valid_instance
      humanized = TestModel.human_attribute_name(attr)

      assert instance.respond_to? "#{attr}_confirmation"
      assert instance.respond_to? "#{attr}_confirmation="

      instance.__send__ "#{attr}=", "password"
      assert instance.valid?

      instance.__send__ "#{attr}_confirmation=", "no match"
      refute instance.valid?

      assert_equal(
        ["#{humanized} confirmation doesn't match #{humanized}"],
        instance.errors.full_messages
      )

      instance.__send__ "#{attr}_confirmation=", "password"
      assert instance.valid?
    end
  end

  test "non_validated does not have a validated confirmation" do
    instance = valid_instance

    refute instance.respond_to? "non_validated_confirmation"
    assert instance.respond_to? "non_validated_confirmation="

    instance.non_validated = "password"
    instance.non_validated_confirmation = "no match"

    assert instance.valid?
  end
end
