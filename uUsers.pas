unit uUsers;

interface

uses Windows, Messages, Classes, SysUtils;

type
  TAuthUser = record
    ServerId: Integer;
    Id: Integer;
    Name: string[20];
    hKey: string[16];
  end;

  PAuthUser = ^TAuthUser;

  TAuthUsers = class
  private

    function GetIndexByName(Name: string): Integer;
    function GetIndexById(Id: Integer): Integer;
    function GetIndex(Id: Integer; Name: string): Integer;
    function DeleteUserByIndex(Index: Integer): Boolean;
  public
    List: TList;

    function GetCount(ServerId: Integer = -1): Integer;
    function GetServerId(Id: Integer; Name: string): Integer;
    function DeleteUser(User: Integer): Boolean; overload;
    function DeleteUser(User: string): Boolean; overload;
    procedure AddUser(ServerId: Integer; Id: Integer; Name: string = '';
      hKey: string = '');
    function DeleteUsers(ServerId: Integer = -1): Integer;
    procedure Clear;

    constructor Create;
    destructor Destroy; override;
  end;

implementation

constructor TAuthUsers.Create;
begin
  List := TList.Create;
end;

destructor TAuthUsers.Destroy;
begin
  FreeAndNil(List);
end;

procedure TAuthUsers.Clear;
var
  I: Integer;
  PU: PAuthUser;
begin
  for I := List.Count - 1 downto 0 do
  begin
    PU := List[I];
    Dispose(PU);
  end;
  List.Clear;
end;

function TAuthUsers.GetCount(ServerId: Integer = -1): Integer;
var
  I: Integer;
  PU: PAuthUser;
begin
  if ServerId < 0 then
  begin
    Result := List.Count;
  end
  else
  begin
    Result := 0;
    for I := 0 to List.Count - 1 do
    begin
      PU := List[I];
      if PU^.ServerId = ServerId then
        Inc(Result);
    end;
  end;
end;

function TAuthUsers.GetIndexByName(Name: string): Integer;
var
  I: Integer;
  PU: PAuthUser;
begin
  Result := -1;
  if Name = '' then
    Exit;

  Name := AnsiLowerCase(Name);
  for I := 0 to List.Count - 1 do
  begin
    PU := List[I];
    if PU^.Name = Name then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

function TAuthUsers.GetIndexById(Id: Integer): Integer;
var
  I: Integer;
  PU: PAuthUser;
begin
  Result := -1;
  if Id <= 0 then
    Exit;

  for I := 0 to List.Count - 1 do
  begin
    PU := List[I];
    if PU^.Id = Id then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

function TAuthUsers.GetIndex(Id: Integer; Name: string): Integer;
begin
  Result := -1;
  if (Result = -1) and (Id <> 0) then
    Result := GetIndexById(Id);
  if (Result = -1) and (Name <> '') then
    Result := GetIndexByName(Name);
end;

function TAuthUsers.GetServerId(Id: Integer; Name: string): Integer;
var
  Index: Integer;
  PU: PAuthUser;
begin
  Index := GetIndex(Id, Name);
  if Index < 0 then
  begin
    Result := -1;
  end
  else
  begin
    PU := List[Index];
    Result := PU^.ServerId;
  end;
end;

procedure TAuthUsers.AddUser(ServerId: Integer; Id: Integer; Name: string = '';
  hKey: string = '');
var
  I: Integer;
  PU: PAuthUser;
begin
  if ServerId < 0 then
    Exit;
  if (Id <= 0) and (Name = '') then
    Exit;

  I := GetIndex(Id, Name);
  if I < 0 then
  begin
    New(PU);
    List.Add(PU);
  end
  else
  begin
    PU := List[I];
  end;

  PU^.ServerId := ServerId;
  PU^.Id := Id;
  PU^.Name := Name;
  PU^.hKey := hKey;
end;

function TAuthUsers.DeleteUserByIndex(Index: Integer): Boolean;
var
  PU: PAuthUser;
begin
  if Index < 0 then
  begin
    Result := False;
  end
  else
  begin
    PU := List[Index];
    List.Delete(Index);
    Dispose(PU);
    Result := True;
  end;
end;

function TAuthUsers.DeleteUser(User: Integer): Boolean;
begin
  Result := DeleteUserByIndex(GetIndexById(User));
end;

function TAuthUsers.DeleteUser(User: string): Boolean;
begin
  Result := DeleteUserByIndex(GetIndexByName(User));
end;

function TAuthUsers.DeleteUsers(ServerId: Integer = -1): Integer;
var
  I: Integer;
  PU: PAuthUser;
begin
  if ServerId < 0 then
  begin
    Result := List.Count;
    Clear;
  end
  else
  begin
    Result := 0;
    for I := List.Count - 1 downto 0 do
    begin
      PU := List[I];
      if PU^.ServerId = ServerId then
      begin
        Inc(Result);
        List.Delete(I);
        Dispose(PU);
      end;
    end;
  end;
end;

end.
