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
  io:format("---------DNS REQUEST---------~n"),
  io:format("IP: ~s~n", [Ip]),
  io:format("Port: ~p~n", [Port]),
  {ok, Socket} = gen_udp:open(0, [binary]),
  ok = gen_udp:send(Socket, Ip, Port, Request),
  Value = receive
            {udp, Socket, _, _, Bin} ->
              {ok, {_, _, _, AA, _, _, _, _, _, QueryCount, AnswerCount, NameserverCount, AdditionalRecordCount}} = process_header(Bin),
              case AA of
                0 ->
                  % Not an authority for domain. Query nameservers provided in response;
                  {ok, NameserverIpAddresses} = extract_nameserver_ip_addresses(Bin, NameserverCount, AdditionalRecordCount),
                  Test = hd(NameserverIpAddresses),
                  {ok, IpAddress} = ip_bitstring_to_string(hd(NameserverIpAddresses)),
                  io:format("The first element is: ~p~n", [Test]),

                  io:format("~n~n"),
                  send_dns_request(Request, IpAddress, Port);
                1 ->
                  % authority for domain. Extract domain from answers and return
                  {ok, Response} = extract_query_section(Bin, QueryCount),
                  io:fwrite("~n~n---------ANSWER RECORDS---------~n"),
                  {ok, AdditionalRecords, AnswerIpAddresses} = extract_answers(Response, [], AnswerCount),
                  {ok, IpAddress} = ip_bitstring_to_string(hd(AnswerIpAddresses)),
                  io:format("IP: ~p~n", [IpAddress]),
                  io:format("~n~n"),
                  {ok, IpAddress}
              end
          after 2000 ->
      error
          end,
  gen_udp:close(Socket),
  Value.

ip_bitstring_to_string(IpBitString) ->
  % Example list of integers
  CharList = binary_to_list(IpBitString),
  StringList = [integer_to_list(Int) || Int <- CharList],
  Delimiter = ".",
  JoinedString = string:join(StringList, Delimiter),
  {ok, JoinedString}.

extract_query_section(Response, QueryCount) ->
  <<Test:96, RemainingPacket/binary>> = Response,
  <<FirstNameLength:8, New/binary>> = RemainingPacket,
  <<FirstName:FirstNameLength/binary, New2/binary>> = New,
  <<SecondNameLength:8, New3/binary>> = New2,
  <<SecondName:SecondNameLength/binary, Trailing:8, New4/binary>> = New3,
  io:fwrite("~n~n---------QUERY SECTION---------~n"),
  io:fwrite("domain name: ~s.~s~n", [FirstName, SecondName]),
  <<Type:16, Class:16, New5/binary>> = New4,
  {ok, New5}.

extract_nameserver_ip_addresses(Response, NameserverCount, AdditionalRecordCount) ->
  <<Test:96, RemainingPacket/binary>> = Response,
  <<FirstNameLength:8, New/binary>> = RemainingPacket,
  <<FirstName:FirstNameLength/binary, New2/binary>> = New,
  <<SecondNameLength:8, New3/binary>> = New2,
  <<SecondName:SecondNameLength/binary, Trailing:8, New4/binary>> = New3,
  io:fwrite("~n~n---------QUERY SECTION---------~n"),
  io:fwrite("domain name: ~s.~s~n", [FirstName, SecondName]),

  <<Type:16, Class:16, New5/binary>> = New4,
  io:fwrite("Type: ~p~n", [Type]),
  io:fwrite("Class: ~p~n", [Class]),

  io:fwrite("~n~n---------AUTHORITATIVE NAMESERVERS---------~n"),
  io:fwrite("Bit string as hex: ~p~n", [binary:encode_hex(New5)]),
  {ok, New6} = extract_authoritative_nameservers(New5, NameserverCount),
  io:fwrite("Bit string as hex: ~p~n", [binary:encode_hex(New6)]),

  io:fwrite("~n~n---------ADDITIONAL RECORDS---------~n"),
  {ok, AdditionalRecords, IpAddresses} = extract_additional_records(New6, [], AdditionalRecordCount),
  io:format("Nameserver IP addresses: ~p~n", [IpAddresses]),
  io:fwrite("Bit string as hex: ~p~n", [binary:encode_hex(AdditionalRecords)]),
  {ok, IpAddresses}.

extract_authoritative_nameservers(AuthoritativeNameservers, 0) ->
  {ok, AuthoritativeNameservers};
extract_authoritative_nameservers(AuthoritativeNameservers, N) ->
  {ok, {NameServer, NewAuthoritativeNameservers}} = extract_authoritative_nameserver(AuthoritativeNameservers),
  io:format("~p. nameserver is: ~s~n", [N, NameServer]),
  extract_authoritative_nameservers(NewAuthoritativeNameservers, N - 1).

extract_authoritative_nameserver(AuthoritativeNameservers) ->
  %%  Name, Type, Class, TTL, DataLength, Data
  <<Name:16, Type:16, Class:16, TTL:32, DataLength:16, Remainder/binary>> = AuthoritativeNameservers,
  <<NameServer:DataLength/binary, Remainder2/binary>> = Remainder,
  {ok, {NameServer, Remainder2}}.

extract_additional_records(AdditionalRecords, IpAddresses, 0) ->
  {ok, AdditionalRecords, IpAddresses};
extract_additional_records(AdditionalRecords, IpAddresses, N) ->
  {ok, {IpAddress, NewAdditionalRecords}} = extract_authoritative_nameserver(AdditionalRecords),
  NewList = append_to_list(IpAddress, IpAddresses),
  extract_additional_records(NewAdditionalRecords, NewList, N - 1).

extract_answers(AnswerRecords, IpAddresses, 0) ->
  {ok, AnswerRecords, IpAddresses};
extract_answers(AnswerRecords, IpAddresses, N) ->
  {ok, {IpAddress, NewAdditionalRecords}} = extract_authoritative_nameserver(AnswerRecords),
  NewList = append_to_list(IpAddress, IpAddresses),
  extract_answers(NewAdditionalRecords, NewList, N - 1).

append_to_list(Element, List) ->
  Length = byte_size(Element),
  if
    Length == 4 ->
      List ++ [Element];
    true ->
      List
  end.

process_header(Response) ->
  io:format("~n~n---------HEADER---------~n"),
  <<ID:16, QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, Z:3, RCODE:4, QDCOUNT:16, ANCOUNT:16, NSCOUNT:16, ARCOUNT:16, _/binary>> = Response,
  io:fwrite("QDCOUNT: ~p~n", [QDCOUNT]),
  io:fwrite("ANCOUNT: ~p~n", [ANCOUNT]),
  io:fwrite("NSCOUNT: ~p~n", [NSCOUNT]),
  io:fwrite("ARCOUNT: ~p~n", [ARCOUNT]),
  {ok, {ID, QR, Opcode, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT}}.
