class MockAuth
  def initialize(is_found, auth_key)
    @is_found = is_found
    @auth_key = auth_key
  end

  attr_reader :auth_key

  def find_by_auth_id(auth_id)
    if @is_found
      self
    else
      nil
    end
  end

  def id
    1
  end
end
