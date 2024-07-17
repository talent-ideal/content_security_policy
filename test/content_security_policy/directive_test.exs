defmodule ContentSecurityPolicy.DirectiveTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ContentSecurityPolicy.Directive
  alias ContentSecurityPolicy.TestHelpers

  describe "validate_directive!/1" do
    property "returns :ok for all keys of the Property struct" do
      Enum.each(TestHelpers.valid_directives(), fn directive ->
        assert Directive.validate_directive!(directive) == :ok
      end)
    end

    property "raises an ArgumentError for any invalid directive" do
      check all(value <- TestHelpers.invalid_directive_generator()) do
        assert_raise(ArgumentError, ~r/Invalid directive/, fn ->
          Directive.validate_directive!(value)
        end)
      end
    end
  end
end
