# Configure Rails Environment
ENV["RAILS_ENV"] = "test"
require 'coerce_boolean'
Warning[:deprecated] = CoerceBoolean.from(ENV['ENABLE_RUBY_DEPRECATED'], strict: true)
Warning[:experimental] = CoerceBoolean.from(ENV['ENABLE_RUBY_EXPERIMENTAL'], strict: true)

require_relative "../test/dummy/config/environment"
ActiveRecord::Migrator.migrations_paths = [File.expand_path("../test/dummy/db/migrate", __dir__)]
require "rails/test_help"
require 'minitest/mock'

require 'nacl_password'
require 'active_support'
require 'active_support/test_case'

# Filter out the backtrace from minitest while preserving the one from other libraries.
Minitest.backtrace_filter = Minitest::BacktraceFilter.new

require "rails/test_unit/reporter"
Rails::TestUnitReporter.executable = 'bin/test'

# Load fixtures from the engine
if ActiveSupport::TestCase.respond_to?(:fixture_path=)
  ActiveSupport::TestCase.fixture_path = File.expand_path("fixtures", __dir__)
  ActionDispatch::IntegrationTest.fixture_path = ActiveSupport::TestCase.fixture_path
  ActiveSupport::TestCase.file_fixture_path = ActiveSupport::TestCase.fixture_path + "/files"
  ActiveSupport::TestCase.fixtures :all
end

class ActiveSupport::TestCase
  # Run tests in parallel with specified workers
  unless CoerceBoolean.from(ENV['SYNC_TEST'])
    # parallelize(workers: :number_of_processors)
  end

  # Add more helper methods to be used by all tests here...

  def assert_is_getter(object, mthd, inst_v = nil)
    inst_v ||= :"@#{mthd}"
    original = object.instance_variable_get(inst_v)
    object.instance_variable_set(inst_v, value = "#{rand}.#{Time.now}")
    assert_equal object.instance_variable_get(inst_v), object.__send__(mthd)
    object.instance_variable_set(inst_v, original)
  end

  def assert_is_setter(object, mthd, inst_v = nil)
    inst_v ||= :"@#{mthd.sub("=", '')}"

    original = object.instance_variable_get(inst_v)
    object.instance_variable_set(inst_v, "#{rand}.#{Time.now}")

    val = (block_given? ? yield : "#{rand}.#{Time.now}")

    refute_equal val, object.instance_variable_get(inst_v)

    object.__send__(mthd, val)

    assert_equal val, object.instance_variable_get(inst_v)

    object.instance_variable_set(inst_v, original)
  end

  def assert_is_accessor(object, mthd, inst_v = nil, &block)
    assert_is_getter object, mthd, inst_v
    assert_is_setter object, "#{mthd}=", inst_v, &block
  end

  def does_call_method(object, method_to_stub, expected: nil, instances: false)
    given = nil
    skip_input = (expected == :skip_input)
    unless expected.present? || skip_input
      expected = []

      (rand(10) + 1).times do
        expected << rand
      end
    end

    stubbed = (
      skip_input ?
        ( ->(*args, **opts) { given = :called_method } ) :
        ( ->(arg) { given = arg } )
    )

    if instances
      object.stub_instances(method_to_stub, stubbed) do
        yield expected
      end
    else
      object.stub(method_to_stub, stubbed) do
        yield expected
      end
    end

    if skip_input
      assert_equal :called_method, given
    else
      assert_equal expected, given
    end

    expected
  end

  def does_call_super_method(object, method_to_stub, expected: nil, &block)
    does_call_method \
      object.class.superclass,
      method_to_stub,
      instances: true,
      expected: expected,
      &block
  end

  def assert_alias_of(object, original_name, aliased_name)
    assert_equal \
      object.method(original_name).original_name,
      object.method(aliased_name).original_name
  end

  def assert_hash_equal(expected, given)
    assert_equal expected.keys.sort, given.keys.sort
    (expected.keys | given.keys).map do |k|
      assert_equal expected[k], given[k]
    end
  end
end
