unit uAuthKeys;

interface

uses Windows, Messages, Classes, SysUtils;

type
  TAuthKeyData = record
    AccountId: Integer;
    AccountName: string;
    SessionId: Integer;
    ServerId: Integer;
    Key: Integer;
    Created: TDateTime;
  end;

  TAuthKeys = class
  private
    Items: array of TAuthKeyData;
    MaxDelay: TDateTime;
    NextCleaning: TDateTime;

    procedure DeleteOldKeys(Forced: Boolean = False);
    function IsValidKeyForIndex(Index: Integer; SessionId: Integer;
      ServerId: Integer; Key: Integer): Boolean;
  public

    function NewKey(AccountId: Integer; AccountName: string; SessionId: Integer;
      ServerId: Integer; Key: Integer = 0): Integer;
    function IsValidKeyForId(AccountId: Integer; SessionId: Integer;
      ServerId: Integer; Key: Integer): Boolean;
    function IsValidKeyForName(AccountName: string; SessionId: Integer;
      ServerId: Integer; Key: Integer): Boolean;

    constructor Create(MaxDelay: Integer = 10);
    destructor Destroy; override;
  end;

implementation

constructor TAuthKeys.Create(MaxDelay: Integer = 10);
begin
  if MaxDelay < 1 then
    MaxDelay := 1;
  if MaxDelay > 59 then
    MaxDelay := 59;
  Self.MaxDelay := EncodeTime(0, 0, MaxDelay, 0);
  NextCleaning := Now;
end;

destructor TAuthKeys.Destroy;
begin
  SetLength(Items, 0);
end;

procedure TAuthKeys.DeleteOldKeys(Forced: Boolean = False);
var
  I, N: Integer;
  T: TDateTime;
begin
  T := Now;
  if (T < NextCleaning) and (not Forced) then
    Exit;
  NextCleaning := T + EncodeTime(0, 3, 0, 0);

  for I := High(Items) downto 0 do
  begin
    if (T < Items[I].Created) or (T - Items[I].Created > MaxDelay) then
    begin
      N := Length(Items) - 1;
      if N <> 0 then
        Items[I] := Items[N];
      SetLength(Items, N);
    end;
  end;
end;

function TAuthKeys.NewKey(AccountId: Integer; AccountName: string;
  SessionId: Integer; ServerId: Integer; Key: Integer = 0): Integer;
var
  I, N: Integer;
begin
  N := -1;
  for I := 0 to High(Items) do
  begin
    if Items[I].AccountId = AccountId then
    begin
      N := I;
      Break;
    end;
  end;
  if N = -1 then
  begin
    N := Length(Items);
    SetLength(Items, N + 1);
  end;

  if Key = 0 then
    Key := Random($FFFFFFFF);

  Items[N].AccountId := AccountId;
  Items[N].AccountName := AnsiLowerCase(AccountName);
  Items[N].SessionId := SessionId;
  Items[N].ServerId := ServerId;
  Items[N].Key := Key;
  Items[N].Created := Now;

  Result := Key;

  DeleteOldKeys;
end;

function TAuthKeys.IsValidKeyForIndex(Index: Integer; SessionId: Integer;
  ServerId: Integer; Key: Integer): Boolean;
var
  T: TDateTime;
begin
  Result := False;

  if (Index < Low(Items)) or (Index > High(Items)) then
    Exit;

  if SessionId <> Items[Index].SessionId then
    Exit;
  if ServerId <> Items[Index].ServerId then
    Exit;
  if Key <> Items[Index].Key then
    Exit;

  T := Now;
  if (T < Items[Index].Created) or (T - Items[Index].Created > MaxDelay) then
    Exit;

  Result := True;
end;

function TAuthKeys.IsValidKeyForId(AccountId: Integer; SessionId: Integer;
  ServerId: Integer; Key: Integer): Boolean;
var
  I: Integer;
begin
  for I := 0 to High(Items) do
  begin
    if AccountId = Items[I].AccountId then
    begin
      Result := IsValidKeyForIndex(I, SessionId, ServerId, Key);
      Exit;
    end;
  end;
  Result := False;
end;

function TAuthKeys.IsValidKeyForName(AccountName: string; SessionId: Integer;
  ServerId: Integer; Key: Integer): Boolean;
var
  I: Integer;
begin
  AccountName := AnsiLowerCase(AccountName);
  for I := 0 to High(Items) do
  begin
    if AccountName = Items[I].AccountName then
    begin
      Result := IsValidKeyForIndex(I, SessionId, ServerId, Key);
      Exit;
    end;
  end;
  Result := False;
end;

begin
  Randomize;

end.
