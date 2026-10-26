class ItemsController < ApplicationController
  has_many :notes
  belongs_to :owner

  def ransackable_attributes(auth_object = nil)
    %w[name owner_id private_note]
  end

  def ransackable_associations(auth_object = nil)
    %w[owner notes]
  end

  def item_params
    params.require(:item).permit(:name, :private_note, :email)
  end
end
