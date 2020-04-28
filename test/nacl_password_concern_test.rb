require 'test_helper'

class NaClPassword::ConcernTest < ActiveSupport::TestCase
  ### SEE dummy/models/test_model and associated tests ###

  class TmpModule < Module; end
  class TmpClass < ActiveRecord::Base; self.table_name = "test_models"; end

  def stub_included_methods
    given = nil

    stubbed_module = ->(*args, **opts) do
      given = [args, opts]
      TmpModule.new
    end

    NaClPassword::Concern::InstanceMethodsOnActivation.stub(:new, stubbed_module) do
      yield
    end

    given
  end

  def stub_validations(object, &block)
    included = []
    validated = length = confirmation = given = nil
    object.stub(:include, ->(arg) {included << arg}) do
      object.stub(:validate, ->(&block) {validated = block}) do
        object.stub(:validates_length_of, ->(*args, **opts) {length = [args, opts]}) do
          object.stub(:validates_confirmation_of, ->(*args, **opts) {confirmation = [args, opts]}) do
            given = stub_included_methods(&block)
          end
        end
      end
    end

    [ included, validated, length, confirmation, given ]
  end

  # assert class methods are defined
  test 'ApplicationRecord::Base responds to :nacl_password' do
    assert ActiveRecord::Base.respond_to? :nacl_password
  end

  test '.nacl_password uses `password` by default for the unencrypted attribute' do
    tmp_class = Class.new(TmpClass)
    args, _opts = stub_included_methods { tmp_class.nacl_password }

    assert_equal :password, args.first
  end

  test '.nacl_password uses `attribute + _digest` by default for the encrypted attribute' do
    tmp_class = Class.new(TmpClass)
    args, _opts = stub_included_methods { tmp_class.nacl_password "tmp" }

    assert_equal :tmp_digest, args.second
  end

  test '.nacl_password accepts a :digest_attribute to use for the encrypted attribute' do
    tmp_class = Class.new(TmpClass)

    args, _opts = stub_included_methods { tmp_class.nacl_password digest_attribute: "test" }

    assert_equal [ :password, :test ], args

    args, _opts = stub_included_methods { tmp_class.nacl_password "tmp", digest_attribute: "test" }

    assert_equal [ :tmp, :test ], args
  end

  test '.nacl_password adds validations by default' do
    tmp_class = Class.new(TmpClass)
    included, validated, length, confirmation, given = stub_validations(tmp_class) do
      tmp_class.nacl_password "tmp"
    end
    _args, instance_opts = given

    expected_length_opts = {
      maximum: NaClPassword::MAX_PASSWORD_LENGTH,
      minimum: 8
    }

    assert included.include?(ActiveModel::Validations)
    assert_instance_of Proc, validated
    assert_equal [ [ :tmp ], expected_length_opts.merge({ allow_blank: true }) ], length
    assert_equal [ [ :tmp ], { allow_blank: true } ], confirmation
    assert_equal expected_length_opts, instance_opts
  end

  test '.nacl_password allows a blank password if :skip_validations == :blank' do
    tmp_class = Class.new(TmpClass)
    included, validated, length, confirmation, given = stub_validations(tmp_class) do
      tmp_class.nacl_password "tmp", skip_validations: :blank
    end

    _args, instance_opts = given

    expected_length_opts = {
      maximum: NaClPassword::MAX_PASSWORD_LENGTH,
      minimum: 8
    }

    assert included.include?(ActiveModel::Validations)
    assert_nil validated
    assert_equal [ [ :tmp ],  expected_length_opts.merge({ allow_blank: true })], length
    assert_equal [ [ :tmp ], { allow_blank: true } ], confirmation
    assert_equal expected_length_opts, instance_opts
  end

  test '.nacl_password does not add a minimum length if :min_length == :none' do
    tmp_class = Class.new(TmpClass)
    included, validated, length, confirmation, given = stub_validations(tmp_class) do
      tmp_class.nacl_password "tmp", min_length: :none
    end

    _args, instance_opts = given

    expected_length_opts = {
      maximum: NaClPassword::MAX_PASSWORD_LENGTH,
    }

    assert included.include?(ActiveModel::Validations)
    assert_instance_of Proc, validated
    assert_equal [ [ :tmp ],  expected_length_opts.merge({ allow_blank: true })], length
    assert_equal [ [ :tmp ], { allow_blank: true } ], confirmation
    assert_equal expected_length_opts, instance_opts
  end

  test '.nacl_password uses the given minimum length if :min_length is set' do
    tmp_class = Class.new(TmpClass)
    included, validated, length, confirmation, given = stub_validations(tmp_class) do
      tmp_class.nacl_password "tmp", min_length: 16
    end

    _args, instance_opts = given

    expected_length_opts = {
      maximum: NaClPassword::MAX_PASSWORD_LENGTH,
      minimum: 16
    }

    assert included.include?(ActiveModel::Validations)
    assert_instance_of Proc, validated
    assert_equal [ [ :tmp ],  expected_length_opts.merge({ allow_blank: true })], length
    assert_equal [ [ :tmp ], { allow_blank: true } ], confirmation
    assert_equal expected_length_opts, instance_opts
  end

  test '.nacl_password does not add any validations if :skip_validations is otherwise truthy' do
    tmp_class = Class.new(TmpClass)
    included, validated, length, confirmation, given = stub_validations(tmp_class) do
      tmp_class.nacl_password "tmp", skip_validations: true
    end

    refute included.include?(ActiveModel::Validations)
    assert_nil validated
    assert_nil length
    assert_nil confirmation
  end

  %w[
    attribute
    attribute=
    attribute_ready?
    attribute_confirmed?
    attribute_length_valid?
    attribute_confirmation=
    authenticate_attribute
  ].each do |method_name|
    get_method_name = ->(attr) { method_name.sub('attribute', attr) }
    desc = get_method_name.call("`attribute`")
    test ".nacl_password adds ##{desc} method" do
      tmp_class = Class.new(TmpClass)

      refute tmp_class.new.respond_to? get_method_name.call("password")
      tmp_class.nacl_password
      assert tmp_class.new.respond_to? get_method_name.call("password")

      %w[
        tmp
        other
        asdf
      ].each do |attr|
        refute tmp_class.new.respond_to? get_method_name.call(attr)
        tmp_class.nacl_password attr
        assert tmp_class.new.respond_to? get_method_name.call(attr)
      end
    end
  end

  test '#`attribute` is a reader for @`attribute`' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password
    tmp_class.nacl_password "tmp"
    assert_is_getter tmp_class.new, :password
    assert_is_getter tmp_class.new, :tmp
  end

  test '#`attribute`= is a setter for @`attribute`' do
    tmp_class = Class.new(TmpClass)
    tmp_class.class_eval <<-EVAL
      attr_accessor :password_digest
      attr_accessor :tmp_digest
    EVAL
    tmp_class.nacl_password
    tmp_class.nacl_password "tmp"
    assert_is_setter tmp_class.new, :password=
    assert_is_setter tmp_class.new, :tmp=
  end

  test '#`attribute`= clears the digest_attribute if empty' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password
    instance = tmp_class.new
    called_with = true
    stub = ->(arg) { called_with = arg }
    instance.stub(:password_digest=, stub) do
      instance.password = nil
    end
    assert_nil called_with
  end

  test '#`attribute`= creates a new digest when not empty' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password
    instance = tmp_class.new
    called_with = nil
    stub = ->(arg) { called_with = arg }
    instance.stub(:password_digest=, stub) do
      instance.password = "password"
    end
    refute_nil called_with
    assert_match /^([^.]+\.){2}(\d+\.){2}\d+$/, called_with
    assert_equal "password", instance.instance_variable_get(:@password)
  end

  test '#authenticate_`attribute`(password) returns `self` if the given password matches' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password
    instance = tmp_class.new

    instance.password = "password"
    assert_equal instance, instance.authenticate_password("password")
    10.times do
      instance.password = password = "#{rand}"
      assert_equal instance, instance.authenticate_password(password)
    end
  end

  test '#authenticate_`attribute`(password) returns `nil` if the given password does not match' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password
    instance = tmp_class.new

    instance.password = "password"
    assert_nil instance.authenticate_password("password2")
  end

  test '#authenticate is an alias for #authenticate_`attribute`(password) if `attribute` is password' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password "tmp"
    instance = tmp_class.new

    refute instance.respond_to? :authenticate
    assert instance.respond_to? :authenticate_tmp

    tmp_class.nacl_password
    instance = tmp_class.new
    assert instance.respond_to? :authenticate
    assert instance.respond_to? :authenticate_password

    tmp_class = Class.new(TmpClass)
    instance = tmp_class.new
    refute instance.respond_to? :authenticate

    tmp_class.nacl_password :password
    instance = tmp_class.new

    assert instance.respond_to? :authenticate
    assert instance.respond_to? :authenticate_password
  end

  test '#`attribute`_ready? returns true if a digest is saved and a new password is not given' do
    tmp_class = Class.new(TmpClass)
    tmp_class.class_eval <<-EVAL
      attr_accessor :password_digest
    EVAL
    tmp_class.nacl_password

    instance = tmp_class.new

    refute instance.password_ready?

    instance.password_digest = "asdf"

    assert instance.password_ready?
  end

  test '#`attribute`_ready? returns true if a valid password and its confirmation matches' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password min_length: :none
    instance = tmp_class.new

    refute instance.password_ready?

    instance.password = "asdf"
    instance.password_confirmation = "asdf"

    assert instance.password_ready?

    instance.password_confirmation = "fdsa"

    refute instance.password_ready?
  end

  test '#`attribute`_ready? returns false if a new password is invalid' do
    tmp_class = Class.new(TmpClass)
    tmp_class.nacl_password
    instance = tmp_class.new

    refute instance.password_ready?

    instance.password = "asdffds"
    instance.password_confirmation = "asdffds"

    refute instance.password_ready?

    instance.password = password = "a" * (NaClPassword::MAX_PASSWORD_LENGTH + 1)
    instance.password_confirmation = password

    refute instance.password_ready?

    instance.password = "asdffdsa"
    instance.password_confirmation = "asdffdsa"

    assert instance.password_ready?
  end
end
