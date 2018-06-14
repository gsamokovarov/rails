# frozen_string_literal: true

module ActionDispatch
  # This middleware guards from DNS rebinding attacks by white-listing the
  # hosts a request can be sent to.
  #
  # When a request comes to an unauthorized host, the +response_app+
  # application will be executed and rendered. If no +response_app+ is given, a
  # default one will run, which responds with +403 Forbidden+.
  class HostAuthorization
    DEFAULT_RESPONSE_APP = -> env do
      request = ActionDispatch::Request.new(env)

      [403, { "Content-Type" => "text/plain" }, [<<~BODY]]
        Requests to #{request.host} are not allowed! To allow them:

          Rails.application.config.hosts << #{request.host.inspect}
      BODY
    end

    def initialize(app, hosts, response_app = nil)
      @app = app
      @hosts = Array(hosts)
      @response_app = response_app || DEFAULT_RESPONSE_APP
    end

    def call(env)
      request = ActionDispatch::Request.new(env)

      if request_allowed?(request)
        @app.call(env)
      else
        @response_app.call(env)
      end
    end

    private

      def request_allowed?(request)
        host = request.host

        @hosts.any? { |allowed| allowed === host }
      end
  end
end
