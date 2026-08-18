%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(cow_cookie).

-export([parse_cookie/1]).
-export([parse_cookie/2]).
-export([parse_set_cookie/1]).
-export([cookie/1]).
-export([setcookie/3]).

-type cookie_attrs() :: #{
	expires => calendar:datetime(),
	max_age => calendar:datetime(),
	domain => binary(),
	path => binary(),
	secure => true,
	http_only => true,
	same_site => default | none | strict | lax
}.
-export_type([cookie_attrs/0]).

-type cookie_opts() :: #{
	domain => binary(),
	http_only => boolean(),
	max_age => non_neg_integer(),
	path => binary(),
	same_site => default | none | strict | lax,
	secure => boolean()
}.
-export_type([cookie_opts/0]).

-type parse_opts() :: #{max_cookies => non_neg_integer()}.
-export_type([parse_opts/0]).

-include("cow_inline.hrl").
-include("cow_parse.hrl").

-ifdef(TEST).
-include_lib("stdlib/include/assert.hrl").
-endif.

%% Cookie header.

-spec parse_cookie(binary()) -> [{binary(), binary()}].
parse_cookie(Cookie) ->
	parse_cookie(Cookie, #{}).

-spec parse_cookie(binary(), parse_opts()) -> [{binary(), binary()}].
parse_cookie(Cookie, Opts) ->
	Max = maps:get(max_cookies, Opts, 100),
	parse_cookie(Cookie, [], Max).

parse_cookie(<<>>, Acc, _) ->
	lists:reverse(Acc);
parse_cookie(<< $\s, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(<< $\t, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(<< $,, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(<< $;, Rest/binary >>, Acc, Max) ->
	parse_cookie(Rest, Acc, Max);
parse_cookie(_, Acc, Max) when length(Acc) =:= Max ->
	error(limit_reached);
parse_cookie(Cookie, Acc, Max) ->
	parse_cookie_name(Cookie, Acc, <<>>, Max).

parse_cookie_name(<<>>, Acc, Name, _) ->
	lists:reverse([{<<>>, parse_cookie_trim(Name)}|Acc]);
parse_cookie_name(<< $=, _/binary >>, _, <<>>, _) ->
	error(badarg);
parse_cookie_name(<< $=, Rest/binary >>, Acc, Name, Max) ->
	parse_cookie_value(Rest, Acc, Name, <<>>, Max);
parse_cookie_name(<< $,, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< $;, Rest/binary >>, Acc, Name, Max) ->
	parse_cookie(Rest, [{<<>>, parse_cookie_trim(Name)}|Acc], Max);
parse_cookie_name(<< $\t, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< $\r, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< $\n, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< $\013, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< $\014, _/binary >>, _, _, _) ->
	error(badarg);
parse_cookie_name(<< C, Rest/binary >>, Acc, Name, Max) ->
	parse_cookie_name(Rest, Acc, << Name/binary, C >>, Max).

parse_cookie_value(<<>>, Acc, Name, Value, _) ->
	lists:reverse([{Name, parse_cookie_trim(Value)}|Acc]);
parse_cookie_value(<< $;, Rest/binary >>, Acc, Name, Value, Max) ->
	parse_cookie(Rest, [{Name, parse_cookie_trim(Value)}|Acc], Max);
parse_cookie_value(<< $\t, _/binary >>, _, _, _, _) ->
	error(badarg);
parse_cookie_value(<< $\r, _/binary >>, _, _, _, _) ->
	error(badarg);
parse_cookie_value(<< $\n, _/binary >>, _, _, _, _) ->
	error(badarg);
parse_cookie_value(<< $\013, _/binary >>, _, _, _, _) ->
	error(badarg);
parse_cookie_value(<< $\014, _/binary >>, _, _, _, _) ->
	error(badarg);
parse_cookie_value(<< C, Rest/binary >>, Acc, Name, Value, Max) ->
	parse_cookie_value(Rest, Acc, Name, << Value/binary, C >>, Max).

parse_cookie_trim(Value = <<>>) ->
	Value;
parse_cookie_trim(Value) ->
	case binary:last(Value) of
		$\s ->
			Size = byte_size(Value) - 1,
			<< Value2:Size/binary, _ >> = Value,
			parse_cookie_trim(Value2);
		_ ->
			Value
	end.

-ifdef(TEST).
parse_cookie_test_() ->
	%% {Value, Result}.
	Tests = [
		{<<"name=value; name2=value2">>, [
			{<<"name">>, <<"value">>},
			{<<"name2">>, <<"value2">>}
		]},
		%% Space in value.
		{<<"foo=Thu Jul 11 2013 15:38:43 GMT+0400 (MSK)">>,
			[{<<"foo">>, <<"Thu Jul 11 2013 15:38:43 GMT+0400 (MSK)">>}]},
		%% Comma in value. Google Analytics sets that kind of cookies.
		{<<"refk=sOUZDzq2w2; sk=B602064E0139D842D620C7569640DBB4C81C45080651"
			"9CC124EF794863E10E80; __utma=64249653.825741573.1380181332.1400"
			"015657.1400019557.703; __utmb=64249653.1.10.1400019557; __utmc="
			"64249653; __utmz=64249653.1400019557.703.13.utmcsr=bluesky.chic"
			"agotribune.com|utmccn=(referral)|utmcmd=referral|utmcct=/origin"
			"als/chi-12-indispensable-digital-tools-bsi,0,0.storygallery">>, [
				{<<"refk">>, <<"sOUZDzq2w2">>},
				{<<"sk">>, <<"B602064E0139D842D620C7569640DBB4C81C45080651"
					"9CC124EF794863E10E80">>},
				{<<"__utma">>, <<"64249653.825741573.1380181332.1400"
					"015657.1400019557.703">>},
				{<<"__utmb">>, <<"64249653.1.10.1400019557">>},
				{<<"__utmc">>, <<"64249653">>},
				{<<"__utmz">>, <<"64249653.1400019557.703.13.utmcsr=bluesky.chic"
					"agotribune.com|utmccn=(referral)|utmcmd=referral|utmcct=/origin"
					"als/chi-12-indispensable-digital-tools-bsi,0,0.storygallery">>}
		]},
		%% Potential edge cases (initially from Mochiweb).
		{<<"foo=\\x">>, [{<<"foo">>, <<"\\x">>}]},
		{<<"foo=;bar=">>, [{<<"foo">>, <<>>}, {<<"bar">>, <<>>}]},
		{<<"foo=\\\";;bar=good ">>,
			[{<<"foo">>, <<"\\\"">>}, {<<"bar">>, <<"good">>}]},
		{<<"foo=\"\\\";bar=good">>,
			[{<<"foo">>, <<"\"\\\"">>}, {<<"bar">>, <<"good">>}]},
		{<<>>, []}, %% Flash player.
		{<<"foo=bar , baz=wibble ">>, [{<<"foo">>, <<"bar , baz=wibble">>}]},
		%% Technically invalid, but seen in the wild
		{<<"foo">>, [{<<>>, <<"foo">>}]},
		{<<"foo ">>, [{<<>>, <<"foo">>}]},
		{<<"foo;">>, [{<<>>, <<"foo">>}]},
		{<<"bar;foo=1">>, [{<<>>, <<"bar">>}, {<<"foo">>, <<"1">>}]}
	],
	[{V, fun() -> R = parse_cookie(V) end} || {V, R} <- Tests].

parse_cookie_error_test_() ->
	%% Value.
	Tests = [
		<<"=">>
	],
	[{V, fun() -> ?assertError(badarg, parse_cookie(V)) end} || V <- Tests].

parse_cookie_max_cookies_test() ->
	Pair = <<"a=b">>,
	%% 100 pairs accepted by default.
	OK = iolist_to_binary(lists:join(<<"; ">>, lists:duplicate(100, Pair))),
	Cookies = parse_cookie(OK),
	100 = length(Cookies),
	%% 101st pair is rejected.
	Over = iolist_to_binary([OK, <<"; ">>, Pair]),
	?assertError(limit_reached, parse_cookie(Over)),
	%% Custom limit: at most N pairs; exceeding errors (no truncation).
	[{<<"a">>, <<"b">>}] = parse_cookie(Pair, #{max_cookies => 1}),
	Two = <<Pair/binary, "; ", Pair/binary>>,
	?assertError(limit_reached, parse_cookie(Two, #{max_cookies => 1})),
	?assertError(limit_reached, parse_cookie(Pair, #{max_cookies => 0})),
	ok.
-endif.

%% Set-Cookie header.

-spec parse_set_cookie(binary())
	-> {ok, binary(), binary(), cookie_attrs()}
	| ignore.
parse_set_cookie(SetCookie) ->
	case has_non_ws_ctl(SetCookie) of
		true ->
			ignore;
		false ->
			{NameValuePair, UnparsedAttrs} = take_until_semicolon(SetCookie, <<>>),
			%% A name-value-pair without '=' is a nameless cookie: the
			%% empty string is the name and the whole pair is the value.
			%% (RFC6265bis 5.5, step 3)
			{Name, Value} = case binary:split(NameValuePair, <<$=>>) of
				[Value0] -> {<<>>, trim(Value0)};
				[Name0, Value0] -> {trim(Name0), trim(Value0)}
			end,
			case {Name, Value} of
				%% Both name and value empty: ignore the
				%% set-cookie-string entirely. (RFC6265bis 5.6, step 2)
				{<<>>, <<>>} ->
					ignore;
				_ ->
					Attrs = parse_set_cookie_attrs(UnparsedAttrs, #{}),
					{ok, Name, Value, Attrs}
			end
	end.

has_non_ws_ctl(<<>>) ->
	false;
has_non_ws_ctl(<<C,R/bits>>) ->
	if
		C =< 16#08 -> true;
		C >= 16#0A, C =< 16#1F -> true;
		C =:= 16#7F -> true;
		true -> has_non_ws_ctl(R)
	end.

parse_set_cookie_attrs(<<>>, Attrs) ->
	Attrs;
parse_set_cookie_attrs(<<$;,Rest0/bits>>, Attrs) ->
	{Av, Rest} = take_until_semicolon(Rest0, <<>>),
	{Name, Value} = case binary:split(Av, <<$=>>) of
		[Name0] -> {trim(Name0), <<>>};
		[Name0, Value0] -> {trim(Name0), trim(Value0)}
	end,
	if
		byte_size(Value) > 1024 ->
			parse_set_cookie_attrs(Rest, Attrs);
		true ->
			case parse_set_cookie_attr(?LOWER(Name), Value) of
				{ok, AttrName, AttrValue} ->
					parse_set_cookie_attrs(Rest, Attrs#{AttrName => AttrValue});
				{ignore, AttrName} ->
					parse_set_cookie_attrs(Rest, maps:remove(AttrName, Attrs));
				ignore ->
					parse_set_cookie_attrs(Rest, Attrs)
			end
	end.

take_until_semicolon(Rest = <<$;,_/bits>>, Acc) -> {Acc, Rest};
take_until_semicolon(<<C,R/bits>>, Acc) -> take_until_semicolon(R, <<Acc/binary,C>>);
take_until_semicolon(<<>>, Acc) -> {Acc, <<>>}.

trim(String) ->
	string:trim(String, both, [$\s, $\t]).

parse_set_cookie_attr(<<"expires">>, Value) ->
	try cow_date:parse_date(Value) of
		DateTime ->
			{ok, expires, DateTime}
	catch _:_ ->
		ignore
	end;
parse_set_cookie_attr(<<"max-age">>, Value = <<C, _/bits>>) when ?IS_DIGIT(C); C =:= $- ->
	try binary_to_integer(Value) of
		MaxAge when MaxAge =< 0 ->
			%% Year 0 corresponds to 1 BC.
			{ok, max_age, {{0, 1, 1}, {0, 0, 0}}};
		MaxAge ->
			CurrentTime = erlang:universaltime(),
			{ok, max_age, calendar:gregorian_seconds_to_datetime(
				calendar:datetime_to_gregorian_seconds(CurrentTime) + MaxAge)}
	catch _:_ ->
		ignore
	end;
parse_set_cookie_attr(<<"domain">>, Value) ->
	case Value of
		<<>> ->
			ignore;
		<<".",Rest/bits>> ->
			{ok, domain, ?LOWER(Rest)};
		_ ->
			{ok, domain, ?LOWER(Value)}
	end;
parse_set_cookie_attr(<<"path">>, Value) ->
	case Value of
		<<"/",_/bits>> ->
			{ok, path, Value};
		%% When the path is not absolute, or the path is empty, the default-path will be used.
		%% Note that the default-path is also used when there are no path attributes,
		%% so we are simply ignoring the attribute here.
		_ ->
			{ignore, path}
	end;
parse_set_cookie_attr(<<"secure">>, _) ->
	{ok, secure, true};
parse_set_cookie_attr(<<"httponly">>, _) ->
	{ok, http_only, true};
parse_set_cookie_attr(<<"samesite">>, Value) ->
	case ?LOWER(Value) of
		<<"none">> ->
			{ok, same_site, none};
		<<"strict">> ->
			{ok, same_site, strict};
		<<"lax">> ->
			{ok, same_site, lax};
		%% Unknown values and lack of value are equivalent.
		_ ->
			{ok, same_site, default}
	end;
parse_set_cookie_attr(_, _) ->
	ignore.

-ifdef(TEST).
parse_set_cookie_test_() ->
	Tests = [
		{<<"a=b">>, {ok, <<"a">>, <<"b">>, #{}}},
		{<<"a=b; Secure">>, {ok, <<"a">>, <<"b">>, #{secure => true}}},
		{<<"a=b; HttpOnly">>, {ok, <<"a">>, <<"b">>, #{http_only => true}}},
		{<<"a=b; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Expires=Wed, 21 Oct 2015 07:29:00 GMT">>,
			{ok, <<"a">>, <<"b">>, #{expires => {{2015,10,21},{7,29,0}}}}},
		{<<"a=b; Max-Age=999; Max-Age=0">>,
			{ok, <<"a">>, <<"b">>, #{max_age => {{0,1,1},{0,0,0}}}}},
		{<<"a=b; Domain=example.org; Domain=foo.example.org">>,
			{ok, <<"a">>, <<"b">>, #{domain => <<"foo.example.org">>}}},
		{<<"a=b; Path=/path/to/resource; Path=/">>,
			{ok, <<"a">>, <<"b">>, #{path => <<"/">>}}},
		{<<"a=b; SameSite=UnknownValue">>, {ok, <<"a">>, <<"b">>, #{same_site => default}}},
		{<<"a=b; SameSite=None">>, {ok, <<"a">>, <<"b">>, #{same_site => none}}},
		{<<"a=b; SameSite=Lax">>, {ok, <<"a">>, <<"b">>, #{same_site => lax}}},
		{<<"a=b; SameSite=Strict">>, {ok, <<"a">>, <<"b">>, #{same_site => strict}}},
		{<<"a=b; SameSite=Lax; SameSite=Strict">>,
			{ok, <<"a">>, <<"b">>, #{same_site => strict}}},
		{<<"a=b; Max-Age=-123">>,
			{ok, <<"a">>, <<"b">>, #{max_age => {{0,1,1},{0,0,0}}}}},
		{<<"a=b; Max-Age=-0">>,
			{ok, <<"a">>, <<"b">>, #{max_age => {{0,1,1},{0,0,0}}}}},
		{<<"a=b; Max-Age=+0">>, {ok, <<"a">>, <<"b">>, #{}}},
		{<<"a=b; Max-Age=+123">>, {ok, <<"a">>, <<"b">>, #{}}}
	],
	[{SetCookie, fun() -> Res = parse_set_cookie(SetCookie) end}
		|| {SetCookie, Res} <- Tests].

%% Only a set-cookie-string with both an empty name and an empty
%% value is ignored entirely. (RFC6265bis 5.6, step 2)
parse_set_cookie_ignore_test_() ->
	Tests = [
		<<>>,
		<<"=">>,
		<<" = ">>,
		<<"=; Secure">>
	],
	[{SetCookie, fun() -> ignore = parse_set_cookie(SetCookie) end}
		|| SetCookie <- Tests].

%% A name-value-pair without '=', or with an empty name, is a
%% nameless cookie: the empty string is the name. (RFC6265bis 5.5,
%% step 3; RFC6265bis 5.6, step 2 only rejects when both are empty.)
parse_set_cookie_nameless_test_() ->
	Tests = [
		{<<"b">>, {ok, <<>>, <<"b">>, #{}}},
		{<<"b; Secure">>, {ok, <<>>, <<"b">>, #{secure => true}}},
		{<<"=b">>, {ok, <<>>, <<"b">>, #{}}},
		{<<"=b; Secure">>, {ok, <<>>, <<"b">>, #{secure => true}}},
		{<<" =b">>, {ok, <<>>, <<"b">>, #{}}},
		%% Only the first '=' separates name from value.
		{<<"=test=2">>, {ok, <<>>, <<"test=2">>, #{}}}
	],
	[{SetCookie, fun() -> Res = parse_set_cookie(SetCookie) end}
		|| {SetCookie, Res} <- Tests].
-endif.

%% Build a cookie header.

-spec cookie([{iodata(), iodata()}]) -> iolist().
cookie([]) ->
	[];
cookie([{<<>>, Value}]) ->
	[ensure_cookie_value(Value)];
cookie([{Name, Value}]) ->
	[ensure_cookie_name(Name), $=, ensure_cookie_value(Value)];
cookie([{<<>>, Value}|Tail]) ->
	[ensure_cookie_value(Value), $;, $\s|cookie(Tail)];
cookie([{Name, Value}|Tail]) ->
	[ensure_cookie_name(Name), $=, ensure_cookie_value(Value), $;, $\s|cookie(Tail)].

-ifdef(TEST).
cookie_test_() ->
	Tests = [
		{[], <<>>},
		{[{<<"a">>, <<"b">>}], <<"a=b">>},
		{[{<<"a">>, <<"b">>}, {<<"c">>, <<"d">>}], <<"a=b; c=d">>},
		{[{<<>>, <<"b">>}, {<<"c">>, <<"d">>}], <<"b; c=d">>},
		{[{<<"a">>, <<"b">>}, {<<>>, <<"d">>}], <<"a=b; d">>},
		%% Empty values are allowed.
		{[{<<"a">>, <<>>}], <<"a=">>},
		%% Values may be enclosed in double quotes.
		{[{<<"a">>, <<"\"b\"">>}], <<"a=\"b\"">>},
		{[{<<"a">>, <<"\"\"">>}], <<"a=\"\"">>},
		%% cookie-octet boundaries.
		{[{<<"a">>, <<16#21>>}], <<"a=", 16#21>>},
		{[{<<"a">>, <<16#23, 16#2b>>}], <<"a=", 16#23, 16#2b>>},
		{[{<<"a">>, <<16#2d, 16#3a>>}], <<"a=", 16#2d, 16#3a>>},
		{[{<<"a">>, <<16#3c, 16#5b>>}], <<"a=", 16#3c, 16#5b>>},
		{[{<<"a">>, <<16#5d, 16#7e>>}], <<"a=", 16#5d, 16#7e>>}
	],
	[{Res, fun() -> Res = iolist_to_binary(cookie(Cookies)) end}
		|| {Cookies, Res} <- Tests].

cookie_error_test_() ->
	Tests = [
		%% Excluded by cookie-octet: SP " , ; \ and DEL.
		[{<<"a">>, <<"b c">>}],
		[{<<"a">>, <<"b\"c">>}],
		[{<<"a">>, <<"b,c">>}],
		[{<<"a">>, <<"b;c">>}],
		[{<<"a">>, <<"b\\c">>}],
		[{<<"a">>, <<"b", 16#7f, "c">>}],
		%% Control characters.
		[{<<"a">>, <<"b", 0, "c">>}],
		[{<<"a">>, <<"b\tc">>}],
		[{<<"a">>, <<"b\rc">>}],
		[{<<"a">>, <<"b\nc">>}],
		[{<<"a">>, <<"b\013c">>}],
		[{<<"a">>, <<"b\014c">>}],
		[{<<"a">>, <<"b", 16#1b, "c">>}],
		%% Non-ASCII.
		[{<<"a">>, <<"b", 16#80, "c">>}],
		%% cookie-octet boundaries.
		[{<<"a">>, <<16#20>>}],
		[{<<"a">>, <<16#22>>}],
		[{<<"a">>, <<16#2c>>}],
		[{<<"a">>, <<16#3b>>}],
		[{<<"a">>, <<16#5c>>}],
		%% A quote must be closed to be a quoted value.
		[{<<"a">>, <<"\"b">>}],
		[{<<"a">>, <<"b\"">>}],
		[{<<"a">>, <<"\"">>}],
		%% Names must be tokens.
		[{<<"a b">>, <<"c">>}],
		[{<<"a=b">>, <<"c">>}],
		[{<<"a;b">>, <<"c">>}],
		[{<<"a,b">>, <<"c">>}],
		[{<<"a\"b">>, <<"c">>}],
		[{<<"a\rb">>, <<"c">>}],
		[{<<"a", 0, "b">>, <<"c">>}],
		%% Checks apply to every cookie in the list.
		[{<<"a">>, <<"b">>}, {<<"c">>, <<"d e">>}],
		[{<<>>, <<"a b">>}]
	],
	[{iolist_to_binary(io_lib:format("~p failure", [V])),
		fun() -> ?assertError(_, iolist_to_binary(cookie(V))) end} || V <- Tests].
-endif.

%% Convert a cookie name, value and options to its iodata form.
%%
%% Initially from Mochiweb:
%%   * Copyright 2007 Mochi Media, Inc.
%% Initial binary implementation:
%%   * Copyright 2011 Thomas Burdick <thomas.burdick@gmail.com>
%%
%% @todo Rename the function to set_cookie eventually.

-spec setcookie(iodata(), iodata(), cookie_opts()) -> iolist().
setcookie(Name, Value, Opts) ->
	[ensure_cookie_name(Name), <<"=">>, ensure_cookie_value(Value),
		attributes(maps:to_list(Opts))].

attributes([]) -> [];
%% The domain is a subdomain as defined in RFC1034 3.5 and RFC1123 2.1,
%% optionally preceded by a dot. We only check for the characters that
%% would allow escaping the attribute, as user agents ignore the dot
%% and lowercase the domain before using it. (RFC6265 5.2.3)
attributes([{domain, Domain}|Tail]) ->
	[<<"; Domain=">>, ensure_attr_value(Domain)|attributes(Tail)];
attributes([{http_only, false}|Tail]) -> attributes(Tail);
attributes([{http_only, true}|Tail]) -> [<<"; HttpOnly">>|attributes(Tail)];
attributes([{max_age, MaxAge}|Tail]) when is_integer(MaxAge), MaxAge >= 0 ->
	[<<"; Max-Age=">>, integer_to_list(MaxAge)|attributes(Tail)];
attributes([Opt={max_age, _}|_]) ->
	error({badarg, Opt});
attributes([{path, Path}|Tail]) ->
	[<<"; Path=">>, ensure_attr_value(Path)|attributes(Tail)];
attributes([{secure, false}|Tail]) -> attributes(Tail);
attributes([{secure, true}|Tail]) -> [<<"; Secure">>|attributes(Tail)];
attributes([{same_site, default}|Tail]) -> attributes(Tail);
attributes([{same_site, none}|Tail]) -> [<<"; SameSite=None">>|attributes(Tail)];
attributes([{same_site, lax}|Tail]) -> [<<"; SameSite=Lax">>|attributes(Tail)];
attributes([{same_site, strict}|Tail]) -> [<<"; SameSite=Strict">>|attributes(Tail)];
%% Skip unknown options.
attributes([_|Tail]) -> attributes(Tail).

-ifdef(TEST).
setcookie_test_() ->
	%% {Name, Value, Opts, Result}
	Tests = [
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{http_only => true, domain => <<"acme.com">>},
			<<"Customer=WILE_E_COYOTE; "
				"Domain=acme.com; HttpOnly">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{path => <<"/acme">>},
			<<"Customer=WILE_E_COYOTE; Path=/acme">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{secure => true},
			<<"Customer=WILE_E_COYOTE; Secure">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{secure => false, http_only => false},
			<<"Customer=WILE_E_COYOTE">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => default},
			<<"Customer=WILE_E_COYOTE">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => none},
			<<"Customer=WILE_E_COYOTE; SameSite=None">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => lax},
			<<"Customer=WILE_E_COYOTE; SameSite=Lax">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{same_site => strict},
			<<"Customer=WILE_E_COYOTE; SameSite=Strict">>},
		{<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{path => <<"/acme">>, badoption => <<"negatory">>},
			<<"Customer=WILE_E_COYOTE; Path=/acme">>}
	],
	[{R, fun() -> R = iolist_to_binary(setcookie(N, V, O)) end}
		|| {N, V, O, R} <- Tests].

%% Max-Age is universally supported by current user agents, so
%% we do not also send an Expires attribute. (RFC6265 4.1.2.2)
setcookie_max_age_test() ->
	F = fun(N, V, O) ->
		binary:split(iolist_to_binary(
			setcookie(N, V, O)), <<";">>, [global])
	end,
	[<<"Customer=WILE_E_COYOTE">>,
		<<" Max-Age=0">>] = F(<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{max_age => 0}),
	[<<"Customer=WILE_E_COYOTE">>,
		<<" Max-Age=111">>,
		<<" Secure">>] = F(<<"Customer">>, <<"WILE_E_COYOTE">>,
			#{max_age => 111, secure => true}),
	?assertError({badarg, {max_age, -111}},
		F(<<"Customer">>, <<"WILE_E_COYOTE">>, #{max_age => -111})),
	[<<"Customer=WILE_E_COYOTE">>,
		<<" Max-Age=86417">>] = F(<<"Customer">>, <<"WILE_E_COYOTE">>,
			 #{max_age => 86417}),
	ok.

setcookie_failures_test_() ->
	F = fun(N, V) ->
		try setcookie(N, V, #{}) of
			_ ->
				false
		catch _:_ ->
			true
		end
	end,
	Tests = [
		{<<"Na=me">>, <<"Value">>},
		{<<"Name;">>, <<"Value">>},
		{<<"\r\name">>, <<"Value">>},
		{<<"Name">>, <<"Value;">>},
		{<<"Name">>, <<"\value">>}
	],
	[{iolist_to_binary(io_lib:format("{~p, ~p} failure", [N, V])),
		fun() -> true = F(N, V) end}
		|| {N, V} <- Tests].

setcookie_attr_failures_test_() ->
	F = fun(Opts) ->
		try setcookie(<<"Name">>, <<"Value">>, Opts) of
			_ ->
				false
		catch _:_ ->
			true
		end
	end,
	Tests = [
		#{path => <<"/a; Secure">>},
		#{domain => <<"ex.com; Path=/">>},
		#{path => [<<"/a">>, <<";HttpOnly">>]},
		%% Control characters.
		#{path => <<"/a\r\nSet-Cookie: b=c">>},
		#{path => <<"/a\nb">>},
		#{path => <<"/a\tb">>},
		#{path => <<"/a", 0, "b">>},
		#{path => <<"/a\013b">>},
		#{path => <<"/a\014b">>},
		#{path => <<"/a", 16#7f, "b">>},
		#{domain => <<"ex.com\r\nSet-Cookie: b=c">>},
		#{domain => <<"ex.com\nb">>},
		#{domain => <<"ex.com", 0, "b">>},
		%% Non-ASCII. Domains must be punycode encoded.
		#{path => <<"/a", 16#80, "b">>},
		#{domain => <<"ex", 16#c3, 16#a9, ".com">>},
		%% path-value boundaries.
		#{path => <<16#1f>>},
		#{path => <<16#3b>>}
	],
	[{iolist_to_binary(io_lib:format("~p failure", [O])),
		fun() -> true = F(O) end}
		|| O <- Tests].

setcookie_attr_test_() ->
	Tests = [
		%% Spaces and other separators are allowed in path-value.
		{#{path => <<"/a b">>}, <<"Name=Value; Path=/a b">>},
		{#{path => <<"/a,b">>}, <<"Name=Value; Path=/a,b">>},
		{#{path => <<"/a=b">>}, <<"Name=Value; Path=/a=b">>},
		{#{path => <<"/a\"b">>}, <<"Name=Value; Path=/a\"b">>},
		%% A leading dot is ignored by user agents.
		{#{domain => <<".example.org">>}, <<"Name=Value; Domain=.example.org">>},
		%% path-value boundaries.
		{#{path => <<16#20>>}, <<"Name=Value; Path=", 16#20>>},
		{#{path => <<16#3a>>}, <<"Name=Value; Path=", 16#3a>>},
		{#{path => <<16#3c>>}, <<"Name=Value; Path=", 16#3c>>},
		{#{path => <<16#7e>>}, <<"Name=Value; Path=", 16#7e>>}
	],
	[{Res, fun() -> Res = iolist_to_binary(setcookie(<<"Name">>, <<"Value">>, O)) end}
		|| {O, Res} <- Tests].
-endif.

%% Validation functions.

%% cookie-name = token (RFC6265 4.1.1)
ensure_cookie_name(Name0) ->
	Name = iolist_to_binary(Name0),
	ok = validate_cookie_name(Name),
	Name.

validate_cookie_name(<<>>) -> ok;
validate_cookie_name(<<C,R/bits>>) when ?IS_TOKEN(C) -> validate_cookie_name(R).

%% cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE ) (RFC6265 4.1.1)
ensure_cookie_value(Value0) ->
	Value = iolist_to_binary(Value0),
	ok = validate_cookie_value(Value),
	Value.

validate_cookie_value(<<$",R/bits>>) when R =/= <<>> ->
	Size = byte_size(R) - 1,
	case R of
		<<V:Size/binary,$">> -> validate_cookie_octets(V);
		_ -> validate_cookie_octets(<<$",R/bits>>)
	end;
validate_cookie_value(Value) ->
	validate_cookie_octets(Value).

validate_cookie_octets(<<>>) -> ok;
validate_cookie_octets(<<C,R/bits>>) when ?IS_COOKIE_OCTET(C) -> validate_cookie_octets(R).

%% path-value and extension-av are any CHAR except CTLs or ";" (RFC6265 4.1.1)
ensure_attr_value(Value0) ->
	Value = iolist_to_binary(Value0),
	ok = validate_attr_value(Value),
	Value.

validate_attr_value(<<>>) -> ok;
validate_attr_value(<<C,R/bits>>) when C >= 16#20, C < 16#7f, C =/= 16#3b ->
	validate_attr_value(R).
