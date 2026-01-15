defmodule ContentSecurityPolicy.Directive do
  @moduledoc """
  Contains functions useful for interacting with Content Security Policy directives.

  Directives are the keys in a content secrurity which define the scope of what
  the source values apply to.

  As an example, in the policy of `"default-src 'self'"`, `default-src` is the
  directive.
  """

  alias ContentSecurityPolicy.Policy

  @opaque valid_directive ::
            :base_uri
            | :child_src
            | :connect_src
            | :default_src
            | :font_src
            | :form_action
            | :frame_ancestors
            | :frame_src
            | :img_src
            | :manifest_src
            | :media_src
            | :object_src
            | :plugin_types
            | :prefetch_src
            | :report_uri
            | :sandbox
            | :script_src
            | :script_src_attr
            | :script_src_elem
            | :style_src
            | :style_src_elem
            | :webrtc
            | :worker_src
            | :require_trusted_types_for

  @doc """
  Returns a list of all valid directives.
  """
  @spec valid_directives() :: list(valid_directive())
  def valid_directives,
    do:
      Policy.__struct__()
      |> Map.keys()
      |> Enum.reject(&(&1 == :__struct__))

  @doc """
  Validates a given directive. Used by other functions in
  `ContentSecurityPolicy`.

  Raises an `ArgumentError` if the directive is not valid.
  """
  @spec validate_directive!(valid_directive()) :: :ok
  def validate_directive!(directive) do
    case directive in valid_directives() do
      true ->
        :ok

      false ->
        raise ArgumentError, """
        Invalid directive (#{inspect(directive)}).

        Directive must be one of the following directives: #{inspect(valid_directives())}
        """
    end
  end
end
