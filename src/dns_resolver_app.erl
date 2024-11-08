-module(dns_resolver_app).
-behaviour(application).

-export([start/2]).
-export([stop/1]).

start(_Type, _Args) ->

  Dispatch = cowboy_router:compile([
    {'_', [
      {"/dns", dns_request_handler, [create]},
      {"/static", cowboy_static, {priv_file, dns_resolver, "static/index.html"}}
    ]}
  ]),
  {ok, _} = cowboy:start_clear(my_http_listener,
    [{port, 8080}],
    #{env => #{dispatch => Dispatch}}
  ),
  dns_resolver_sup:start_link().

stop(_State) ->
  ok.
