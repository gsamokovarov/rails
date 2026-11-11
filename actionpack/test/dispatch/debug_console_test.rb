# frozen_string_literal: true

require "abstract_unit"

class DebugConsoleTest < ActionDispatch::IntegrationTest
  class Boom < StandardError; end

  # rubocop:disable Lint/Debugger
  App = ->(env) do
    request = ActionDispatch::Request.new(env)
    answer = 42

    case request.path
    when "/console"
      binding.console
      [200, { "content-type" => "text/html", "content-length" => "28" }, ["<html><body>Hi</body></html>"]]
    when "/cached", "/cached_console"
      binding.console if request.path == "/cached_console"
      [200, { "content-type" => "text/html", "cache-control" => "max-age=0, private, must-revalidate" }, ["<html><body>Hi</body></html>"]]
    when "/fragment"
      binding.console
      [200, { "content-type" => "text/html" }, ["Hi"]]
    when "/json"
      binding.console
      [200, { "content-type" => "application/json" }, ["{}"]]
    when "/console_boom"
      binding.console
      -> { later = :raised; raise Boom, "boom with #{later}" }.call
    when "/boom"
      raise Boom, "boom with #{answer}"
    when "/cause"
      begin
        cause = :inner
        raise Boom, "boom with #{cause}"
      rescue Boom
        outer = :outer
        raise "boom with #{outer}"
      end
    else
      [200, { "content-type" => "text/html" }, ["<html><body>Hi</body></html>"]]
    end
  end
  # rubocop:enable Lint/Debugger

  setup do
    @app = build_app(App)
  end

  test "does not render a console unless requested" do
    get "/", headers: local

    assert_equal "<html><body>Hi</body></html>", response.body
  end

  test "renders a console for Binding#console" do
    get "/console", headers: local

    assert_match %r{<script nonce="" data-url="/rails/console/\h{32}">.*</script></body></html>\z}m, response.body
    assert_equal response.body.bytesize.to_s, response.headers["content-length"]
  end

  test "renders a console at the end of pages without a body tag" do
    get "/fragment", headers: local

    assert_match %r{\AHi<script nonce="" data-url="[^"]+">.*</script>\z}m, response.body
  end

  test "renders a console with the content security policy nonce" do
    get "/console", headers: local.merge("action_dispatch.content_security_policy_nonce" => "secret")

    assert_includes response.body, %(<script nonce="secret" )
  end

  test "prevents the pages with a console from being cached" do
    get "/cached_console", headers: local

    assert_match(/script/, response.body)
    assert_equal "no-store", response.headers["cache-control"]
  end

  test "keeps the caching headers of the pages without a console" do
    get "/cached", headers: local

    assert_equal "max-age=0, private, must-revalidate", response.headers["cache-control"]
  end

  test "renders a console for the pages the browser revalidates" do
    @app = build_app(Rack::ConditionalGet.new(Rack::ETag.new(App)))

    get "/console"
    conditions = { "HTTP_IF_NONE_MATCH" => response.headers["etag"], "HTTP_IF_MODIFIED_SINCE" => Time.now.httpdate }

    get "/console", headers: local.merge(conditions, "HTTP_SEC_FETCH_DEST" => "document")
    assert_response :ok
    assert_match(/script/, response.body)
  end

  test "keeps the conditional requests that are not page loads" do
    @app = build_app(Rack::ConditionalGet.new(Rack::ETag.new(App)))

    get "/"
    etag = response.headers["etag"]

    get "/", headers: local.merge("HTTP_IF_NONE_MATCH" => etag)
    assert_response :not_modified

    get "/", headers: local.merge("HTTP_IF_NONE_MATCH" => etag, "HTTP_SEC_FETCH_DEST" => "empty")
    assert_response :not_modified
  end

  test "keeps the conditional page loads of remote requests" do
    @app = build_app(Rack::ConditionalGet.new(Rack::ETag.new(App)))

    get "/"
    etag = response.headers["etag"]

    get "/", headers: local.merge("HTTP_IF_NONE_MATCH" => etag, "HTTP_SEC_FETCH_DEST" => "document", "REMOTE_ADDR" => "172.18.0.1")
    assert_response :not_modified
  end

  test "does not render a console in non HTML responses" do
    get "/json", headers: local

    assert_equal "{}", response.body
  end

  test "does not render a console for remote requests" do
    get "/console", headers: local.merge("REMOTE_ADDR" => "172.18.0.1")
    assert_no_match(/script/, response.body)

    get "/boom", headers: local.merge("REMOTE_ADDR" => "172.18.0.1")
    assert_no_match(/rails\/console/, response.body)
  end

  test "does not render a console for requests forwarded for remote addresses" do
    get "/console", headers: local.merge("HTTP_X_FORWARDED_FOR" => "203.0.113.7")
    assert_no_match(/script/, response.body)

    get "/console", headers: local.merge("HTTP_X_FORWARDED_FOR" => "203.0.113.7, 127.0.0.2")
    assert_no_match(/script/, response.body)
  end

  test "does not render a console for requests forwarded by remote proxies" do
    get "/console", headers: local.merge("REMOTE_ADDR" => "10.0.0.1", "HTTP_X_FORWARDED_FOR" => "127.0.0.1")

    assert_no_match(/script/, response.body)
  end

  test "does not render a console for remote addresses in the other forwarding headers" do
    get "/console", headers: local.merge("HTTP_CLIENT_IP" => "203.0.113.7")
    assert_no_match(/script/, response.body)

    get "/console", headers: local.merge("HTTP_FORWARDED" => "for=203.0.113.7, for=127.0.0.1")
    assert_no_match(/script/, response.body)

    get "/console", headers: local.merge("HTTP_FORWARDED" => "for=127.0.0.1", "HTTP_X_FORWARDED_FOR" => "203.0.113.7")
    assert_no_match(/script/, response.body)
  end

  test "does not render a console for requests from UNIX sockets" do
    get "/console", headers: local.merge("REMOTE_ADDR" => "unix:")

    assert_no_match(/script/, response.body)
  end

  test "does not render a console for spoofed addresses" do
    output = StringIO.new

    get "/console", headers: local.merge(
      "HTTP_CLIENT_IP" => "127.0.0.1",
      "HTTP_X_FORWARDED_FOR" => "127.0.0.2",
      "action_dispatch.logger" => Logger.new(output),
    )

    assert_no_match(/script/, response.body)
    assert_includes output.string, "Cannot render console from [Spoofed]!"
  end

  test "renders a console for local requests forwarded by local proxies" do
    get "/console", headers: local.merge("HTTP_X_FORWARDED_FOR" => "127.0.0.2")
    assert_match(/script/, response.body)

    get "/console", headers: local.merge("HTTP_FORWARDED" => 'for="[::1]:4711", for=127.0.0.3')
    assert_match(/script/, response.body)
  end

  test "renders a console for IPv6 localhost requests" do
    get "/console", headers: local.merge("REMOTE_ADDR" => "::1", "HTTP_X_FORWARDED_FOR" => "::ffff:127.0.0.1")

    assert_match(/script/, response.body)
  end

  test "renders a console for the allowed addresses" do
    @app = build_app(App, ["172.16.0.0/12", IPAddr.new("203.0.113.7")])

    get "/console", headers: local.merge("REMOTE_ADDR" => "172.18.0.1", "HTTP_X_FORWARDED_FOR" => "203.0.113.7")
    assert_match(/script/, response.body)

    get "/console", headers: local.merge("REMOTE_ADDR" => "172.18.0.1", "HTTP_X_FORWARDED_FOR" => "203.0.113.8")
    assert_no_match(/script/, response.body)
  end

  test "allows a single network" do
    @app = build_app(App, "172.16.0.0/12")

    get "/console", headers: local.merge("REMOTE_ADDR" => "172.31.255.254")
    assert_match(/script/, response.body)

    get "/console", headers: local
    assert_match(/script/, response.body)
  end

  test "allows a single address" do
    @app = build_app(App, IPAddr.new("203.0.113.7"))

    get "/console", headers: local.merge("REMOTE_ADDR" => "203.0.113.7")
    assert_match(/script/, response.body)

    get "/console", headers: local.merge("REMOTE_ADDR" => "203.0.113.8")
    assert_no_match(/script/, response.body)
  end

  test "logs the requests a console cannot be rendered for" do
    output = StringIO.new

    get "/console", headers: local.merge("REMOTE_ADDR" => "172.18.0.1", "action_dispatch.logger" => Logger.new(output))

    assert_includes output.string, "Cannot render console from 172.18.0.1! Allowed networks: 127.0.0.0/8, ::1/128, ::ffff:127.0.0.0/104"
  end

  test "does not leak the binding into the next request" do
    get "/console", headers: local
    get "/", headers: local

    assert_no_match(/script/, response.body)
  end

  test "evaluates code in the binding" do
    get "/console", headers: local

    assert_equal({ "output" => "=> 43" }, console(input: "answer + 1"))
  end

  test "keeps the local variables defined in the console" do
    get "/console", headers: local

    console(input: "question = answer * 2")

    assert_equal({ "output" => "=> 84" }, console(input: "question"))
  end

  test "renders the errors of the evaluated code" do
    get "/console", headers: local

    assert_match(/\ANameError: undefined local variable or method 'nope'/, console(input: "nope")["error"])
    assert_match(/\ASyntaxError: /, console(input: ")")["error"])
    assert_no_match(/debug_console\.rb/, console(input: "raise 'oops'")["error"])
  end

  test "completes the last word of the input" do
    get "/console", headers: local

    assert_equal ["answer"], console(complete: "ans")["candidates"]
    assert_includes console(complete: "answer.to_")["candidates"], "answer.to_s"
    assert_includes console(complete: "ActionDispatch::Debug")["candidates"], "ActionDispatch::DebugConsole"
    assert_empty console(complete: "nope.")["candidates"]
  end

  test "does not evaluate code for remote requests" do
    get "/console", headers: local

    post console_path, params: { input: "1" }, headers: local.merge("REMOTE_ADDR" => "172.18.0.1")

    assert_equal "<html><body>Hi</body></html>", response.body
  end

  test "responds with not found for unknown consoles" do
    post "/rails/console/#{"0" * 32}", params: { input: "1" }, headers: local

    assert_response :not_found
    assert_match(/no longer available/, response.parsed_body["error"])
  end

  test "forgets the oldest consoles" do
    get "/console", headers: local
    oldest = console_path

    ActionDispatch::DebugConsole::MAX_SESSIONS.times { get "/console", headers: local }
    post oldest, params: { input: "1" }, headers: local

    assert_response :not_found
  end

  test "renders a console on error pages" do
    get "/boom", headers: local

    assert_response :internal_server_error
    assert_equal({ "output" => "=> 42" }, console(input: "answer"))
  end

  test "evaluates code in the selected frame of an error page" do
    get "/boom", headers: local

    frame = css_select(".trace-frames").find { |link| link.text.include?("debug_exceptions.rb") }
    params = { exception: frame["data-exception-object-id"], frame: frame["data-frame-id"] }

    assert_equal({ "output" => "=> ActionDispatch::DebugExceptions" }, console(input: "self.class", **params))
    assert_equal({ "error" => "There is no binding available for this frame." }, console(input: "1", **params, frame: 10_000))
  end

  test "evaluates code in the frames of the causes of an exception" do
    get "/cause", headers: local

    outer, inner = css_select(".trace-frames").map { |link| link["data-exception-object-id"] }.uniq
    outer_frame, inner_frame = [outer, inner].map do |exception|
      css_select(".trace-frames[data-exception-object-id='#{exception}']").find { |link| link.text.include?(__FILE__) }["data-frame-id"]
    end

    assert_equal({ "output" => "=> :outer" }, console(input: "outer"))
    assert_equal({ "output" => "=> :inner" }, console(input: "cause", exception: inner, frame: inner_frame))
    assert_equal({ "output" => "=> :outer" }, console(input: "outer", exception: outer, frame: outer_frame))
  end

  test "prefers the exception over the requested console" do
    get "/console_boom", headers: local

    frame = css_select(".trace-frames").find { |link| link.text.include?("block in") && link.text.include?(__FILE__) }
    params = { exception: frame["data-exception-object-id"], frame: frame["data-frame-id"] }

    assert_equal({ "output" => "=> :raised" }, console(input: "later"))
    assert_equal({ "output" => "=> 42" }, console(input: "answer", **params))
  end

  test "renders the requested console on error pages without the debug gem" do
    stub_const(ActionDispatch, :DEBUG_AVAILABLE, false) do
      get "/console_boom", headers: local
    end

    assert_response :internal_server_error
    assert_equal({ "output" => "=> 42" }, console(input: "answer"))
    assert_match(/undefined local variable or method 'later'/, console(input: "later")["error"])
  end

  test "does not render a console on error pages without the debug gem" do
    stub_const(ActionDispatch, :DEBUG_AVAILABLE, false) do
      get "/boom", headers: local
    end

    assert_response :internal_server_error
    assert_no_match(/rails\/console/, response.body)
  end

  private
    def build_app(app, allowed_ips = nil)
      Rack::Lint.new(
        ActionDispatch::DebugConsole.new(
          Rack::Lint.new(
            ActionDispatch::DebugExceptions.new(app),
          ),
          allowed_ips,
        ),
      )
    end

    def local
      { "action_dispatch.show_detailed_exceptions" => true, "action_dispatch.show_exceptions" => :all }
    end

    def console_path
      response.body[%r{/rails/console/\h{32}}]
    end

    def console(**params)
      @console_path ||= console_path
      post @console_path, params: params, headers: local
      response.parsed_body
    end
end
