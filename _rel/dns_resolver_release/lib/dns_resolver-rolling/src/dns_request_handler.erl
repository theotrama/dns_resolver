-module(dns_request_handler).
-behavior(cowboy_handler).

-export([init/2, content_types_accepted/2, allowed_methods/2, resolve_dns_query/2, content_types_provided/2]).

-import(resolver, [run/1]).


init(Req, State) ->
  {cowboy_rest, Req, State}.

allowed_methods(Req, State) ->
  {[<<"POST">>], Req, State}.

content_types_accepted(Req, State) ->
  {[
    {<<"application/json">>, resolve_dns_query}
  ], Req, State}.

content_types_provided(Req, State) ->
  {[
    {<<"application/json">>, resolve_dns_query}
  ], Req, State}.


resolve_dns_query(Req, State) ->
  io:fwrite("~nTest~n"),
  io:fwrite("State: ~p~n", [State]),
  io:fwrite("Request: ~p~n", [Req]),
  io:fwrite("Has body? ~p~n", [cowboy_req:has_body(Req)]),


  {ok, ReqBody, _} = cowboy_req:read_body(Req),
  io:fwrite("RequestBody: ~p~n", [ReqBody]),
  RequestBodyDecoded = jsx:decode(ReqBody),
  io:fwrite("RequestBody: ~p~n", [RequestBodyDecoded]),
  Query = maps:get(<<"query">>, RequestBodyDecoded),
  {ok, _} = resolve_domain(Query),
  {true, Req, State}.


resolve_domain(Query) ->
  io:fwrite("Query: ~p~n", [Query]),
  {ok, Response} = run("google.com"),
  io:fwrite("Response: ~p~n", [Response]),
  {ok, "_"}.
