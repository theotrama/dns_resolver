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
-export([run/1]).
-import(string, [tokens/2, concat/2]).

-record(authority_record, {name,type, class,ttl, data_length, nameserver_name}).
-record(additional_record, {name,type, class,ttl, data_length, ip}).


run(Domain) ->
  {ok, DnsRequest} = build_dns_request(Domain),
  {ok, DnsResponse} = send_dns_request(DnsRequest, "199.7.83.42", 53),
  parse_dns_response(DnsResponse).

build_dns_request(DomainName) ->
  TransactionId = [63, 144],
  Flags = [1, 0],
  NumberOfQuestions = [0, 1],
  AnswerResourceRecords = [0, 0],
  AuthorityResourceRecords = [0, 0],
  AdditionalResourceRecords = [0, 0],

  QueryList = string:tokens(DomainName, "."),


  QueryListTransformed = lists:map(fun(X) -> [length(X), lists:map(fun(Y) -> [Y] end, X)] end, QueryList),
  QueryListFlattened = lists:flatten(QueryListTransformed),

  QueryEnd = [0],
  RecordType = [0, 1],
  Class = [0, 1],

  InitialRequestPacket = lists:flatten([TransactionId, Flags, NumberOfQuestions,
    AnswerResourceRecords, AuthorityResourceRecords, AdditionalResourceRecords,
    QueryListFlattened, QueryEnd, RecordType, Class]),

  io:format("Request packet: ~p~n", [InitialRequestPacket]),
  {ok, InitialRequestPacket}.


send_dns_request(Request, Ip, Port) ->
  io:format("---------DNS REQUEST---------~n"),
  io:format("IP: ~s~n", [Ip]),
  io:format("Port: ~p~n", [Port]),
  {ok, Socket} = gen_udp:open(0, [binary]),
  ok = gen_udp:send(Socket, Ip, Port, Request),
  Value = receive
            {udp, Socket, _, _, Bin} ->
              {ok, Bin}
          after 2000 ->
      error
          end,
  gen_udp:close(Socket),
  Value.


parse_dns_response(DnsResponse) ->
 {ok, {_, _, _, AA, _, _, _, _, _, QueryCount, AnswerCount, NameserverCount, AdditionalRecordCount}} = parse_header_section(DnsResponse),
 {ok, RemainingDnsResponse, {QueryName, Type, Class}} = parse_query_records(DnsResponse, QueryCount),
  io:format("~n~n---------QUERY SECTION---------~n"),
  io:fwrite("Name:  ~p~n", [QueryName]),
  io:fwrite("Type:  ~p~n", [Type]),
  io:fwrite("Class: ~p~n", [Class]),

  io:format("~n~n---------AUTHORITY RECORD SECTION---------~n"),
  {ok, RemainingDnsResponse2, AuthorityRecords} = parse_authority_records(DnsResponse, RemainingDnsResponse, NameserverCount),
  io:fwrite("~p~n", [AuthorityRecords]),
  io:fwrite("Remaining DNS packet: ~p~n", [RemainingDnsResponse2]),


  io:format("~n~n---------ADDITIONAL RECORD SECTION---------~n"),
  {ok, TheEnd, AdditionalRecords} = parse_additional_records(DnsResponse, RemainingDnsResponse2, AdditionalRecordCount),
  io:fwrite("~p~n", [AdditionalRecords]),
  io:fwrite("Remaining DNS packet: ~p~n", [TheEnd]),

 {ok, "DnsRecord"}.

parse_header_section(Response) ->
  io:format("~n~n---------HEADER---------~n"),
  <<ID:16, QR:1, Opcode:4, AA:1, TC:1, RD:1, RA:1, Z:3, RCODE:4, QDCOUNT:16, ANCOUNT:16, NSCOUNT:16, ARCOUNT:16, _/binary>> = Response,
  io:fwrite("Questions:     ~p~n", [QDCOUNT]),
  io:fwrite("Answer RRs:    ~p~n", [ANCOUNT]),
  io:fwrite("Authority RRs: ~p~n", [NSCOUNT]),
  io:fwrite("Additonal RRs: ~p~n", [ARCOUNT]),
  {ok, {ID, QR, Opcode, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT}}.

parse_additional_records(DnsResponse, RemainingDnsResponse, 0) ->
    {ok, RemainingDnsResponse, []};
parse_additional_records(DnsResponse, RemainingDnsResponse, AdditionalRecordCount) ->
  {ok, Name, NewRemainingDnsResponse} = parse_name(DnsResponse, RemainingDnsResponse),
  <<Type:16, Class:16, Ttl:32, DataLength:16, RemainingDnsResponse2/binary>> = NewRemainingDnsResponse,
  DataLengthBytes = DataLength,
  <<Data:DataLengthBytes/binary, RemainingDnsResponse3/binary>> = RemainingDnsResponse2,
  Ip = inet:ntoa(list_to_tuple(binary_to_list(Data))),
  io:fwrite("IP: ~p~n", [Ip]),

  case Ip of
    {error, einval} -> AdditionalRecord = #additional_record{name=Name, type=Type, class=Class, ttl=Ttl, data_length=DataLength, ip="IPv6"};
    Otherwise -> AdditionalRecord = #additional_record{name=Name, type=Type, class=Class, ttl=Ttl, data_length=DataLength, ip=Ip}
  end,

  {ok, _, NewAdditionalRecord} = parse_additional_records(DnsResponse, RemainingDnsResponse3, AdditionalRecordCount - 1),

  FullList = lists:append([AdditionalRecord], NewAdditionalRecord),
  {ok, RemainingDnsResponse3, FullList}.

parse_authority_records(DnsResponse, RemainingDnsResponse, 0) ->
    {ok, RemainingDnsResponse, []};
parse_authority_records(DnsResponse, RemainingDnsResponse, AuthorityRecordCount) ->
  {ok, Name, NewRemainingDnsResponse} = parse_name(DnsResponse, RemainingDnsResponse),
  <<Type:16, Class:16, Ttl:32, DataLength:16, RemainingDnsResponse2/binary>> = NewRemainingDnsResponse,
  DataLengthBytes = DataLength * 8,
  <<Data:DataLengthBytes, RemainingDnsResponse3/binary>> = RemainingDnsResponse2,

  {ok, NameserverName, _} = parse_name(DnsResponse, RemainingDnsResponse2),

  AuthorityRecord = #authority_record{name=Name, type=Type, class=Class, ttl=Ttl, data_length=DataLength, nameserver_name=NameserverName},

  {ok, RemainingDnsResponse4, NewAuthorityRecord} = parse_authority_records(DnsResponse, RemainingDnsResponse3, AuthorityRecordCount - 1),

  FullList = lists:append([AuthorityRecord], NewAuthorityRecord),
  {ok, RemainingDnsResponse4, FullList}.

parse_query_records(DnsResponse, 0) ->
  {ok, DnsResponse};
parse_query_records(DnsResponse, QueryCount) ->
  io:fwrite("Resource records: ~p~n", [DnsResponse]),
  <<_:96, ResourceRecords/binary>> = DnsResponse,
  io:fwrite("Resource records: ~p~n", [ResourceRecords]),
  {ok, FullName, RemainingDnsResponse} = parse_name(DnsResponse, ResourceRecords),
  io:fwrite("Full name is: ~p~n", [FullName]),
  io:fwrite("Remaining packet is: ~p~n", [RemainingDnsResponse]),

  <<Type:16, Class:16, NewRemainingDnsResponse/binary>> = RemainingDnsResponse,
  io:fwrite("Type is: ~p~n", [Type]),
  io:fwrite("Class is: ~p~n", [Class]),
  parse_query_records(DnsResponse, QueryCount - 1),
  {ok, NewRemainingDnsResponse, {FullName, Type, Class}}.


parse_name(DnsResponse, RemainingDnsResponse) ->
  <<Length:8, Remainder/binary>> = RemainingDnsResponse,
  case Length of
    0 ->
      <<_:8, NewRemainingDnsResponse/binary>> = RemainingDnsResponse,
      {ok, "", NewRemainingDnsResponse};
    192 ->
      <<_:8, Offset:8, X/binary>> = RemainingDnsResponse,
      <<_:Offset/binary, OffsetResponse/binary>> = DnsResponse,
      {ok, Name, _} = parse_name(DnsResponse, OffsetResponse),
      <<_:16, NewRemainingDnsResponse/binary>> = RemainingDnsResponse,
      {ok, Name, NewRemainingDnsResponse};
    Otherwise ->
      <<NamePart:Length/binary, Remainder2/binary>> = Remainder,
      {ok, NamePart2, NewRemainingDnsResponse} = parse_name(DnsResponse, Remainder2),
      FullName = lists:append([binary_to_list(NamePart)], NamePart2),
      {ok, FullName, NewRemainingDnsResponse}
  end.
