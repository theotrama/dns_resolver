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
-export([run/0]).


run() ->
  Request = "\x3f\x90\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
  Ip = "199.7.83.42",
  Port = 53,
  send_dns_request(Request, Ip, Port).


send_dns_request(Request, Ip, Port) ->
  {ok, Socket} = gen_udp:open(0, [binary]),
  ok = gen_udp:send(Socket, Ip, Port, Request),
  Value = receive
            {udp, Socket, _, _, Bin} ->
              process_header(Bin),
              {ok, Bin}
          after 2000 ->
      error
          end,
  gen_udp:close(Socket),
  Value.

process_header(Response) ->
  <<TransactionId:16/binary, QR:1/binary, Opcode:4/binary, Remainder/binary>> = Response,
  io:format(TransactionId),
  io:format("\n"),
  io:format(QR),
  io:format("\n"),
  io:format(Opcode),
  io:format("\n"),
  io:format(Remainder).
