%%%-------------------------------------------------------------------
%%% @author jankoch
%%% @copyright (C) 2023, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 01. May 2023 16:48
%%%-------------------------------------------------------------------
-module(udp_server).
-author("jankoch").

%% API
-export([run/0]).


-import(resolver, [send_dns_request/3]).


run() ->
  {ok, Socket} = gen_udp:open(53, [binary]),
  loop(Socket).
loop(Socket) ->
  receive
    {udp, Socket, Host, Port, Bin} ->
      {ok, ResolvedIp} = send_dns_request(Bin, "199.7.83.42", 53),

      gen_udp:send(Socket, Host, Port, ResolvedIp),
      loop(Socket)
  end.