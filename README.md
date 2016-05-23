# Exauth

**TODO: Add description**

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add exauth to your list of dependencies in `mix.exs`:

        def deps do
          [{:exauth, "~> 0.0.1"}]
        end

  2. Ensure exauth is started before your application:

        def application do
          [applications: [:exauth]]
        end

## TODO List

- [ ] Each store should be independent. One for tokens, auth-codes, clients and users.

