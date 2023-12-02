-module(dns_request_handler).
-behavior(cowboy_handler).

-export([init/2, content_types_accepted/2, allowed_methods/2, resolve_dns_query/2, content_types_provided/2]).

-import(resolver, [run/1]).

-record(additional_record, {name, type, class, ttl, data_length, ip}).


init(Req, State) ->
  {cowboy_rest, Req, State}.

allowed_methods(Req, State) ->
  {[<<"POST">>], Req, State}.

content_types_provided(Req, State) ->
  {[
    {<<"application/json">>, resolve_dns_query}
  ], Req, State}.

content_types_accepted(Req, State) ->
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
  {ok, Ips} = resolve_domain(Query),
  io:fwrite("Ips: ~p~n", [Ips]),
  ResponseBody = jsx:encode(Ips),
  io:fwrite("ResponseBody: ~p~n", [ResponseBody]),

  NewIps = lists:map(fun(Ip) -> iolist_to_binary(Ip) end, Ips),
  io:fwrite("ResponseBody: ~p~n", [NewIps]),

  Response = #{<<"answers">> => NewIps},


  %% Set response headers
  Headers = #{<<"content-type">> => <<"application/json">>},

  %% Send the response
  {ok, Reply} = cowboy_req:reply(200, Headers, jsx:encode(Response), Req),
  {true, Reply, State}.


resolve_domain(Query) ->
  io:fwrite("Query: ~p~n", [Query]),
  {ok, AnswerRecords} = run(binary:bin_to_list(Query)),
  io:fwrite("Response: ~p~n", [AnswerRecords]),


  Ips = lists:map(fun(AnswerRecord) -> AnswerRecord#additional_record.ip end, AnswerRecords),
  {ok, Ips}.
