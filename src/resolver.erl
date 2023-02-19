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
              {ok, {_, _, _, AA, _, _}} = process_header(Bin),
              case AA of
                0 -> do; % Not an authority for domain. Query nameservers provided in response;
                1 -> do % authority for domain. Extract domain from answers and return
              end,
              {ok, Bin}
          after 2000 ->
      error
          end,
  gen_udp:close(Socket),
  Value.

extract_domain(Response) ->
  {noreply, Response}.

extract_nameserver_ip(Response) ->
  {noreply, Response}.

build_dns_query(Ip, Port, Domain) ->
  {noreply, Ip, Port, Domain}.

process_header(Response) ->
  <<ID:16, QR:1, Opcode:4, AA:1, TC:1, RD:1, Remainder/binary>> = Response,
  {ok, {ID, QR, Opcode, AA, TC, RD}}.
