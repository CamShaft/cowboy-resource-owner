-module(cowboy_resource_owner).

-export([execute/2]).
-export([init/1]).

-export([client_id/1]).
-export([owner_id/1]).
-export([scopes/1]).
-export([is_authenticated/1]).
-export([failed_authentication/1]).
-export([is_authorized/2]).

-record (resource_auth, {
  client_id :: binary(),
  owner_id :: binary(),
  expiration :: calendar:datetime(),
  scopes :: [binary()],
  other :: term()
}).

execute(Req, Env) ->
  case fast_key:get(token_handler, Env) of
    undefined ->
      undefined;
    TokenHandler ->
      Fun = init(TokenHandler),
      Fun(Req, Env)
  end.

init(Handler) when is_function(Handler) ->
  fun (Req, Env) ->
    Value = case get_token(Req) of
      undefined ->
        undefined;
      Token ->
        case Handler(Token, Env) of
          {ClientID, OwnerID, Scopes, Expiration, Other} ->
            #resource_auth{client_id = ClientID,
                           owner_id = OwnerID,
                           scopes = Scopes,
                           expiration = Expiration,
                           other = Other};
          {error, _} = Error ->
            Error;
          _ ->
            {error, invalid_token}
        end
    end,
    Req2 = cowboy_req:set_meta(resource_auth, Value, Req),
    {ok, Req2, Env}
  end;
init(Handler) ->
  init(fun Handler:handle/2).

client_id(Req) ->
  {Info, Req} = cowboy_req:meta(resource_auth, Req),
  case Info of
    {error, _} = Error -> Error;
    #resource_auth{client_id = ClientID} -> ClientID;
    undefined -> undefined;
    _ -> {error, invalid_token_info}
  end.

owner_id(Req) ->
  {Info, Req} = cowboy_req:meta(resource_auth, Req),
  case Info of
    {error, _} = Error -> Error;
    #resource_auth{owner_id = OwnerID} -> OwnerID;
    undefined -> undefined;
    _ -> {error, invalid_token_info}
  end.

scopes(Req) ->
  {Info, Req} = cowboy_req:meta(resource_auth, Req),
  case Info of
    {error, _} = Error -> Error;
    #resource_auth{scopes = Scopes} -> Scopes;
    undefined -> undefined;
    _ -> {error, invalid_token_info}
  end.

is_authenticated(Req) ->
  case client_id(Req) of
    {error, _} -> false;
    _ -> true
  end.

failed_authentication(Req) ->
  {Info, Req} = cowboy_req:meta(resource_auth, Req),
  case Info of
    undefined ->
      false;
    {error, _} ->
      true;
    _ ->
      false
  end.

is_authorized(RequiredScope, Req) when is_binary(RequiredScope) ->
  is_authorized([RequiredScope], Req);
is_authorized(RequiredScopes, Req) when is_list(RequiredScopes) ->
  case scopes(Req) of
    OwnerScopes when is_list(OwnerScopes) ->
      check_scopes(RequiredScopes, gb_sets:from_list(OwnerScopes));
    _ ->
      false
  end.

check_scopes([], _) ->
  true;
check_scopes([RequiredScope|RequiredScopes], OwnerScopes) ->
  case gb_sets:is_member(RequiredScope, OwnerScopes) of
    false ->
      false;
    true ->
      check_scopes(RequiredScopes, OwnerScopes)
  end.

%% TODO add more ways to authenticate
get_token(Req) ->
  case cowboy_req:parse_header(<<"authorization">>, Req) of
    {ok, {<<"bearer">>, AccessToken}, _} ->
      AccessToken;
    _ ->
      undefined
  end.
