# frozen_string_literal: true

require "abstract_unit"

class HostAuthorizationTest < ActionDispatch::IntegrationTest
  App = -> env { [200, {}, %w(Success)] }

  BlockedApp = ActionDispatch::HostAuthorization.new(App, %w(only.com))
  AllowedApp = ActionDispatch::HostAuthorization.new(App, %w(www.example.com))
  DynamicApp = ActionDispatch::HostAuthorization.new(App, [-> input { input == "www.example.com" }])
  CustomApp = ActionDispatch::HostAuthorization.new(App, %w(only.com), -> env { [401, {}, %w(Custom)] })

  test "blocks requests to unallowed host" do
    @app = BlockedApp

    get "/"

    assert_response :forbidden
    assert_equal <<~EXPECTED, body
      Requests to www.example.com are not allowed! To allow them:

        Rails.application.config.hosts << "www.example.com"
    EXPECTED
  end

  test "allows requests to allowed host" do
    @app = AllowedApp

    get "/"

    assert_response :ok
    assert_equal "Success", body
  end

  test "checks for requests with #=== to support wider range of host checks" do
    @app = DynamicApp

    get "/"

    assert_response :ok
    assert_equal "Success", body
  end

  test "blocks requests to unallowed host supporting custom responses" do
    @app = CustomApp

    get "/"

    assert_response :unauthorized
    assert_equal "Custom", body
  end
end
