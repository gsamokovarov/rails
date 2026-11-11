# frozen_string_literal: true

require_relative "../abstract_unit"
require "active_support/core_ext/binding"

class BindingExtTest < ActiveSupport::TestCase
  teardown do
    ActiveSupport::IsolatedExecutionState.delete(:debug_console)
  end

  test "console requests a console in the binding" do
    current = binding

    assert_nil current.console
    assert_same current, ActiveSupport::IsolatedExecutionState[:debug_console]
  end

  test "console requests a console in the last binding" do
    first, last = binding, binding
    first.console
    last.console

    assert_same last, ActiveSupport::IsolatedExecutionState[:debug_console]
  end
end
