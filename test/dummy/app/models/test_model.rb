class TestModel < ApplicationRecord
  nacl_password min_length: 4
  nacl_password :no_minimum, min_length: :none
  nacl_password :test_non_standard, digest_attribute: :non_standard_attr, skip_validations: :blank
  nacl_password :non_validated, skip_validations: true
end
