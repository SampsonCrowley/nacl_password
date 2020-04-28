class CreateTestModels < ActiveRecord::Migration[6.0]
  def change
    create_table :test_models do |t|
      t.text :password_digest
      t.text :no_minimum_digest
      t.text :non_standard_attr
      t.text :non_validated_digest

      t.timestamps
    end
  end
end
