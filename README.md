# exauth - OAuth 2 based simple authentication system for Elixir

Status: Alpha. Currently undergoing development. Not yet suitable for
production usage.

This is a port of the [clauth](https://github.com/pelle/clauth)
project. It is a simple OAuth 2 provider that is designed to be used
as a primary authentication provider for an Elixir app.

It currently handles OAuth2 bearer authentication and interactive
authentication.

See [draft-ietf-oauth-v2-bearer](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08)

The following bearer tokens are implemented:

* [Authorization header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.1)
* [Form encoded body parameter](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.2)
* [URI query field](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.3)
* Non standard http cookie ('access_token') for use in interactive applications
* Non standard session ('access_token') for use in interactive applications

## Install

TODO: Add to hex

## Usage

There are currently 2 middlewares defined:

* Middleware.wrap_bearer_token
* Middleware.require_bearer_token!

Both of them take as a parameter a function which should return a
object representing the token. This could be a user object, but could
also be a token object with specific meta-data. 

The object returned by your function is set to :access_token entry in
the request.

The difference between wrap_bearer_token and require_bearer_token! is
that wrap will find a token but not require it. require_bearer_token
will return a
[HTTP 401 header](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-08#section-2.4).

## Grant Types

Currently the following Grant types are supported:

* [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1)
* [Client Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.4)
* [Resource Owner Password Credential Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.3)

## Authorization request

We currently support the following authorization requests:

* [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1)
* [Implicit Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2)

You can control the ones you wish to support by using the
configuration parameter :allowed_response_types to the
authorization_handler

```elixir
Exauth.Endpoints.authorization_handler %{:allows_response_types ["code"]} # Only support Authorization Code Grants
```

Implement custom authorization requests:

```elixir
Exauth.Endpoints.authorization_request_handler("custom", conn, options)
```

## Tokens

There is a protocol defined called Expirable which implements one function:

```elixir
is_valid? token
```

This is implementend by Map so %{} represents a valid token where
{:expires date} is invalid.

A OAuthToken map can be instantiated and stored easily by the
create_token function:

```elixir
create_token(client, user)
```

## Users

A User map exists which can be instantiated and stored easily by the register_user function:

```elixir
Exauth.User.register_user login password name url
```

## Stores

Stores are used to store tokens and will be used to store clients and
users as well.

There is a generalized protocol called Store and currently a simple
memory implementation used for it.

It should be pretty simple to implement this Store with redis, sql,
datomic or what have you.

The following stores are currently defined:

* token_store is in Exauth.Token.token_store
* auth_code_store is in Exauth.AuthCode>auth_code_store
* client_store is in Exauth.Client/client_store
* user_store is in Exauth.User/user_store

## Authorization OAuth Tokens

There is currently a single authorization handler that handles
authorization called authorization_handler. Install it in your routes
by convention at "/authorize" or "/oauth/authorize".

Authorization handler comes with defaults that use the various built
in token, user etc. stores. You can override these by passing in a
configuration map containing functions.

```elixir
authorization_handler %{authorization_form: &Exauth.Views.authorization_form_handler/1
                        client_lookup: &Exauth.Client.fetch_client/1
                        token_lookup: &Exauth.Token.fetch_token/1
                        token_creator: &Exauth.Token.create_token/1
                        auth_code_creator: &Exauth.AuthCode.create_auth_code/1}
```

## Issuing OAuth Tokens

There is currently a single token-handler that provides token issuance
called token_handler. Install it in your routes by convention at
"/token" or "/oauth/token".

Token handler comes with defaults that use the various built in token,
user etc. stores. You can override these by passing in a configuration
map containing functions.

```elixir
Exauth.Endpoints.token_handler %{client-authenticator: &Exauth.Client.authenticate_client/1
                                 user-authenticator: &Exauth.User.authenticate_user/1
                                 token-creator: &Exauth.Token.create_token/1
                                 auth-code-revoker: &Exauth.AuthCode.revoke_auth_code!/1
                                 auth-code-lookup: &Exauth.AuthCode.fetch_auth_code/1 })
```

## Using as primary user authentication on server

One of the ideas of this is using OAuth tokens together with
traditional sessions based authentication providing the benefits of
both. To do this we create a new token when a user logs in and adds it
to the session.

Why is this a good idea?

* You will be able to view a list of other sessions going on for
  security purposes
* You will be able to remotely log of another session
* Your app deals with tokens only. So this is also ideal for an API
  with a javascript front end

To use this make sure to wrap the session middleware. We have a login
handler endpoint that could be used like this:

TODO: convert
```clojure
(defn routes [master-client]
  (fn [req]
  (case (req :uri)
    "/login" ((login-handler master-client) req)
    ((require-bearer-token! handler) req))))
```

The master-client is a client record representing your own
application. A default login view is defined in
clauth.views/login-form-handler but you can add your own. This just
needs to be a ring handler presenting a form with the parameters
"username" and "password".

```clojure
(defn routes [master-client]
  (fn [req]
  (case (req :uri)
    "/login" ((login-handler my-own-login-form-handler master-client) req)
    ((require-bearer-token! handler) req))))
```

## Run Demo App

A mini server demo is available. It creates a client for you and
prints out instructions on how to issue tokens with curl.

```
lein run -m clauth.demo
```

## TODO

The goal is to implement the full
[OAuth2 spec](http://tools.ietf.org/html/draft-ietf-oauth-v2-25). The
only main feature missing is. I'll aim for that for 1.1 as most people
currently don't use refresh tokens:

* [Refresh Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-1.5)

## Contribute

You will need to have a Redis database running in the background in
order to have some of the tests pass, otherwise, you will get an error
about the connection being refused.

If you have Homebrew on Mac OSX, you can get Redis by typing ```brew
install redis``` in the command line. Once that's done, get the Redis
database started in your Terminal window by typing the following:

```
redis-server /usr/local/etc/redis.conf
```

## License

Copyright (C) 2012 Pelle Braendgaard http://stakeventures.com

Distributed under the Eclipse Public License, the same as Clojure.
