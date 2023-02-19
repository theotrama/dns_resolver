%%%-------------------------------------------------------------------
%%% @author jankoch
%%% @copyright (C) 2023, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 19. Feb 2023 10:53
%%%-------------------------------------------------------------------
-module(resolver).
-author("jankoch").

%% API
-export([hello_world/0]).


hello_world() -> io:fwrite("hello, world\n").


send_dns_request(Request) ->
  {ok, Socket} = gen_udp:open(0, [binary]),
  ok = gen_udp:send(Socket, "199.7.83.42", 53, Request),
  Value = receive
            () -> io:fwrite("hello, world\n")
          end,
  gen_udp:close(Socket),
  Value.