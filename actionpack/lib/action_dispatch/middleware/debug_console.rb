# frozen_string_literal: true

require "ipaddr"
require "securerandom"
require "active_support/core_ext/module/attribute_accessors"
require "active_support/core_ext/object/json"
require "active_support/core_ext/erb/util"
require "active_support/core_ext/binding"
require "action_dispatch/middleware/exception_wrapper"

begin
  require "debug/frame_info"
  ActionDispatch::DEBUG_AVAILABLE = true # :nodoc:
rescue LoadError
  ActionDispatch::DEBUG_AVAILABLE = false # :nodoc:
end

module ActionDispatch
  # # Action Dispatch DebugConsole
  #
  # This middleware renders an interactive Ruby console at the bottom of the
  # HTML pages. The console evaluates code on the server, in the binding it was
  # requested for with `Binding#console`:
  #
  #     class PostsController < ApplicationController
  #       def index
  #         @posts = Post.all
  #         binding.console
  #       end
  #     end
  #
  # When the [debug](https://github.com/ruby/debug) gem is available, a console
  # is rendered on the error pages of ActionDispatch::DebugExceptions as well.
  # It starts in the frame the source extract is shown for and follows the
  # trace frames selected on the page.
  #
  # The console executes arbitrary Ruby code, so the middleware is only meant
  # for development and only serves the requests coming from localhost. To use
  # it from other addresses, like the ones of a Docker network, allow them with
  # `config.action_dispatch.debug_console_allowed_ips`:
  #
  #     config.action_dispatch.debug_console_allowed_ips = "172.16.0.0/12"
  #
  # The address of a request is resolved like ActionDispatch::RemoteIp does,
  # except that only the allowed addresses are trusted as proxies and requests
  # with conflicting forwarding headers are never served.
  class DebugConsole
    cattr_accessor :endpoint, default: "/rails/console"

    LOCALHOST = %w[127.0.0.0/8 ::1 ::ffff:127.0.0.0/104].freeze # :nodoc:
    MAX_SESSIONS = 32 # :nodoc:
    SCRIPT = File.read(File.expand_path("templates/debug/console.js", __dir__)) # :nodoc:

    def initialize(app, allowed_ips = nil)
      @app = app
      @allowed_ips = [*LOCALHOST, *allowed_ips].map { |ip| ip.is_a?(IPAddr) ? ip : IPAddr.new(ip) }
      @sessions = {}
      @session_path = %r{\A#{Regexp.escape(endpoint)}/(\h+)\z}
    end

    def call(env)
      request = ActionDispatch::Request.new(env)
      request_allowed = allowed?(request)

      if request_allowed && request.post? && (id = request.path[@session_path, 1])
        return evaluate(request, id)
      end

      if request_allowed && request.get_header("HTTP_SEC_FETCH_DEST") == "document"
        request.delete_header("HTTP_IF_NONE_MATCH")
        request.delete_header("HTTP_IF_MODIFIED_SINCE")
      end

      frames = {}.compare_by_identity
      response = capture_frames(frames) { @app.call(env) }
      bindings = bindings_for(request, frames)

      if bindings.nil? || request.head? || !response[1][Rack::CONTENT_TYPE].to_s.include?("html")
        response
      elsif request_allowed
        inject(request, response, bindings)
      else
        request.logger&.info "Cannot render console from #{strict_remote_ip(request)}! " \
          "Allowed networks: #{@allowed_ips.map { |ip| "#{ip}/#{ip.prefix}" }.join(", ")}"
        response
      end
    ensure
      ActiveSupport::IsolatedExecutionState.delete(:debug_console)
    end

    private
      def allowed?(request)
        ip = strict_remote_ip(request)
        @allowed_ips.any? { |allowed| allowed.include?(ip) }
      rescue IPAddr::Error
        false
      end

      def strict_remote_ip(request)
        RemoteIp::GetIp.new(request, true, @allowed_ips).to_s
      rescue RemoteIp::IpSpoofAttackError
        "[Spoofed]"
      end

      def capture_frames(frames, &block)
        return yield unless DEBUG_AVAILABLE

        TracePoint.new(:raise) do |trace|
          frames[trace.raised_exception] ||= DEBUGGER__.capture_frames(nil)
        end.enable(&block)
      end

      def bindings_for(request, frames)
        bindings = {}

        if exception = request.get_header("action_dispatch.debug_exception")
          wrapper = ExceptionWrapper.new(request.get_header("action_dispatch.backtrace_cleaner"), exception)

          [wrapper, *wrapper.wrapped_causes].each do |wrapped|
            remaining = frames[wrapped.unwrapped_exception].to_a

            wrapped.exception.backtrace_locations&.each_with_index do |location, index|
              position = remaining.index { |frame| frame.location.path == location.path && frame.location.lineno == location.lineno }
              next unless position

              binding = remaining[position].binding
              bindings[[wrapped.exception_id, index]] = binding if binding
              remaining = remaining.drop(position + 1)
            end
          end

          bindings[nil] = bindings[[wrapper.exception_id, wrapper.source_to_show_id]] || bindings.values.first
        end

        bindings[nil] ||= ActiveSupport::IsolatedExecutionState[:debug_console]
        bindings if bindings[nil]
      end

      def inject(request, (status, headers, body), bindings)
        return [status, headers, body] unless body.respond_to?(:to_ary)

        id = SecureRandom.hex(16)
        @sessions[id] = bindings
        @sessions.shift if @sessions.size > MAX_SESSIONS

        url = "#{request.script_name}#{endpoint}/#{id}"
        nonce = request.get_header("action_dispatch.content_security_policy_nonce")
        script = %(<script nonce="#{nonce}" data-url="#{ERB::Util.html_escape(url)}">#{SCRIPT}</script>)

        html = body.to_ary.join
        html.insert(html.rindex("</body>") || -1, script)
        headers[Rack::CONTENT_LENGTH] = html.bytesize.to_s if headers[Rack::CONTENT_LENGTH]

        headers[Rack::CACHE_CONTROL] = "no-store"

        [status, headers, [html]]
      end

      def evaluate(request, id)
        params = request.params
        bindings = @sessions[id]
        frame = [params[:exception].to_i, params[:frame].to_i] if params[:frame]

        if bindings.nil?
          render 404, error: "This console is no longer available on the server. Reload the page to get a new one."
        elsif !(binding = bindings[frame])
          render 200, error: "There is no binding available for this frame."
        elsif word = params[:complete]
          render 200, candidates: complete(binding, word)
        else
          render 200, **execute(binding, params[:input].to_s)
        end
      end

      def execute(binding, input)
        { output: "=> #{binding.eval(input, *binding.source_location).inspect}" }
      rescue Exception => error
        backtrace = (error.backtrace.to_a - caller).reject { |line| line.start_with?(__FILE__) }

        { error: ["#{error.class.name}: #{error.message}", *backtrace.map { |line| "\tfrom #{line}" }].join("\n") }
      end

      def complete(binding, word)
        receiver, separator, prefix = word.rpartition(/\.|::/)

        sources = if separator.empty?
          %w[local_variables instance_variables methods class_variables global_variables Object.constants]
        else
          ["(#{receiver}).methods", "(#{receiver}).constants"]
        end

        candidates = sources.flat_map do |source|
          binding.eval(source)
        rescue Exception
          []
        end

        candidates.filter_map { |name| "#{receiver}#{separator}#{name}" if name.start_with?(prefix) }.uniq.sort
      end

      def render(status, **body)
        body = body.to_json

        [status, { Rack::CONTENT_TYPE => "application/json; charset=utf-8", Rack::CONTENT_LENGTH => body.bytesize.to_s }, [body]]
      end
  end
end
