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
              {ok, {_, _, _, AA, _, _, _, _, _, _, _, _, _}} = process_header(Bin),
              case AA of
                0 ->
                  % Not an authority for domain. Query nameservers provided in response;
                  {ok, NameserverIp} = extract_nameserver_ip(Bin),
                  {ok, NewRequest} = build_dns_query(NameserverIp, Port, "google.com"),
                  send_dns_request(NewRequest, NameserverIp, Port);
                1 ->
                  % authority for domain. Extract domain from answers and return
                  {ok, get_a_record(Bin)}
              end
          after 2000 ->
      error
          end,
  gen_udp:close(Socket),
  Value.

get_a_record(Response) ->
  {ok, "123.123.123.123"}.

extract_nameserver_ip(Response) ->
  <<Test:96, FirstNameLength:8, Type:16, Class:24, _/binary>> = Response,
  io:fwrite("Length of first part: ~p~n", [FirstNameLength]),
  <<Test:96, FirstNameLength:8, Type:16, Class:24, _/binary>> = Response,

  <<_:96, Name:96, Type:16, Class:24, _/binary>> = Response,
  <<Length:8, Rest/binary>> = <<Name>>,
  io:fwrite("Length: ~p~n", [Length]),
  io:fwrite("Bit string as hex: ~p~n", [binary:encode_hex(Response)]),
  io:fwrite("Name string as hex: ~p~n", [Length]),


  Pixel = <<213, 45, 132, 64, 76, 32, 76, 0, 0, 234, 32, 15>>,
  io:fwrite("Length: ~p~n", [Length]),
  io:fwrite("Length: ~p~n", [Response]),
  io:fwrite("Bit string as hex: ~p~n", [binary:encode_hex(Pixel)]),
  <<_:8, First:Length, _/binary>> = Response,


  <<_:96, Name:96, Type:16, Class:24, _/binary>> = Response,
  io:fwrite("Type: ~p~n", [binary:encode_hex(<<1, 2, 3, 4, 5, 6, 255>>)]),
  io:fwrite("Type: ~p~n", [Class]),
  {ok, "199.7.83.42"}.

build_dns_query(Ip, Port, Domain) ->
  {ok, "Request"}.

process_header(Response) ->
  <<ID:16, QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, Z:3, RCODE:4, QDCOUNT:16, ANCOUNT:16, NSCOUNT:16, ARCOUNT:16, _/binary>> = Response,
  {ok, {ID, QR, Opcode, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT}}.
