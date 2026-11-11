# frozen_string_literal: true

require "active_support/isolated_execution_state"

class Binding
  # Requests an interactive Ruby console, evaluating code in this binding, at
  # the bottom of the page rendered for the current request.
  #
  # ```
  # class PostsController < ApplicationController
  #   def index
  #     @posts = Post.all
  #     binding.console
  #   end
  # end
  # ```
  #
  # Returns `nil`, so it renders nothing when called from a view. If called
  # more than once during a request, the console opens in the last binding.
  #
  # The console is rendered by the `ActionDispatch::DebugConsole` middleware.
  # Without it, calling this method has no effect.
  def console
    ActiveSupport::IsolatedExecutionState[:debug_console] = self
    nil
  end
end
