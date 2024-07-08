unit uFunc;

interface

uses SysUtils, Windows, Messages, Classes, cHash, Registry, libeay32, WinSock,
  uBlowFish, Graphics, Masks, ComCtrls, md5, StrUtils;

type
  TMsgType = (mtError, mtFunc, mtDefault, mtInfo, mtUser, mtWelcome, mtServer,
    mtGuard, mtGuardNotice);

  TGuard = record
    Pck, Error: Boolean;
    hKey: string;
    ClientCRC, GuardCRC: LongWord;
    Cheat: Integer;
    inf: array [0 .. 15] of byte;
  end;

  TMyTimer = record
    Next: Cardinal;
    Interval: Cardinal;
    Enabled: Boolean;
  end;

  TClient = record
    Account, Password, IP: string;
    Addr: TSockAddr;
    SID: Integer;
    LRKey: string;
    Guard: TGuard;
    UID: Integer;
    LoginOK: Boolean;
    LastId: byte;
    LastWorld: byte;
    Tick: Cardinal;
    TraderAdv: Boolean;
    Trader: Boolean;
    LoginFlag: Integer;
    WarnFlag: Integer;
    SpecialGates: byte;
    Tester: Boolean;

    Recv: record
      Pck: string;
      Buf: string;
      Enabled: Boolean;
    end;
  end;

  TLog = record
    Enabled: Boolean;
    filename: string;
    f: TextFile;
  end;

  TServerAddrPart = record
    Special: byte;
    Subnets: array of string;
    IP: array of Integer;
  end;

  TServerAddr = array of TServerAddrPart;

var
  title: string;
  LastDay: word;

function CheckCRC(crc: Integer; original: string): Boolean;
function RSAGenerateKeys(var PrivateKey: pRSA; var PublicKey: string;
  Len: Integer = 1024): Boolean;
function ScrambleRSA(key: string): string;
function InitXOR(s: string): string;
procedure s2c(Pck: string; n: Integer; Recv: Boolean = true;
  blowfish: Boolean = true; crc: Boolean = true);
procedure WriteD(var Pck: string; v: Integer; ind: Integer = 0);
function ReplaceInvalidCharacters(s: string): string;
procedure LoadOptions(Silent: Boolean = False);
procedure ATL(Text: string; MsgType: TMsgType = mtDefault;
  Color: TColor = clBlack);
function StrToHex(s: string; Space: Boolean = False): string;
function HexToText(s: string): string;
function GetSockError(ErrorCode: Integer): string;
procedure s2s(Pck: string; ServerIndex: Integer);
procedure WriteC(var Pck: string; v: byte; ind: Integer = 0);
procedure WriteH(var Pck: string; v: Integer; ind: Integer = 0);
function EncryptPassword(str: string): string;
procedure EIF(msg: string; code: Integer = 0);
procedure AddToBlack(d: TClient);
function CheckTimer(var t: TMyTimer; new: Boolean = False): Boolean;
function MyMatchesMask(IP, mask: string): Boolean;
procedure InitLog(var l: TLog; name: string);
function md5(s: string): string;
function crypt(Password: string): string;
function StrToIP(s: string): Integer;
function IPToStr(IP: Integer): string;
function ServerAddrToString(Addr: TServerAddr): string;
function StringToServerAddr(Data: string): TServerAddr;
function SelectIPFromServerAddr(Addr: TServerAddr; IP: string;
  Special: byte): Integer;
function UniToStr(WideStr: string): string;
function StrToUni(ustr: string): string;
procedure Explode(Separator: Char; s: string; Strings: TStringList;
  Limit: Integer = 0);

implementation

uses uMain, uDebug;

procedure Explode(Separator: Char; s: string; Strings: TStringList;
  Limit: Integer = 0);
var
  I, n: Integer;
  Start: Integer;
  Done: Boolean;
begin
  Strings.BeginUpdate;
  try
    Strings.Clear;
    if s = '' then
      Exit;
    n := 0;
    Start := 1;
    Done := False;
    repeat
      Inc(n);
      I := PosEx(Separator, s, Start);
      if (I = 0) or (n = Limit) then
      begin
        I := Length(s) + 1;
        Done := true;
      end;
      Strings.Add(Copy(s, Start, I - Start));
      Start := I + 1;
    until Done;
  finally
    Strings.EndUpdate;
  end;
end;

function UniToStr(WideStr: string): string;
var
  I, n: Integer;
  C: Char;
  Len: Integer;
begin
  Len := Length(WideStr);
  if (Len = 0) or (Len mod 2 <> 0) then
  begin
    Result := '';
    Exit;
  end;

  Len := Len div 2;
  SetLength(Result, Len);
  n := 1;
  for I := 1 to Len do
  begin
    C := WideStr[n];
    if C = #0 then
    begin
      SetLength(Result, I - 1);
      Exit;
    end;
    if WideStr[n + 1] = #4 then
    begin
      case C of
        #$51:
          C := '¸';
        #$01:
          C := '¨';
      else
        Inc(C, $B0);
      end;
    end;
    Result[I] := C;
    Inc(n, 2);
  end;
end;

function StrToUni(ustr: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(ustr) do
  begin
    C := ustr[I];
    if (C in ['à' .. 'ÿ', 'À' .. 'ß']) then
      Result := Result + chr(ord(C) - $B0) + #$04
    else
      Result := Result + C + #$00;
  end;
  Result := Result + #0#0;
end;

function StrToIP(s: string): Integer;
var
  I, n: Integer;
  X: array [1 .. 4] of byte;
  Y: Integer absolute X;
begin
  Result := 0;
  s := s + '.';
  try
    for n := 1 to 4 do
    begin
      I := Pos('.', s);
      if I < 1 then
        Exit;
      X[n] := StrToIntDef(Copy(s, 1, I - 1), 0);
      Delete(s, 1, I);
    end;
    Result := Y;
  except
    Result := 0;
  end;
end;

function IPToStr(IP: Integer): string;
var
  a: array [0 .. 3] of byte;
  I: Integer absolute a;
begin
  I := IP;
  Result := Format('%d.%d.%d.%d', [a[0], a[1], a[2], a[3]]);
end;

function StringToServerAddrPart(Data: string;
  var Part: TServerAddrPart): Boolean;
var
  List, List2: TStringList;
  I, J: Integer;
  s: string;

  function ProcessFlags(s: string): Boolean;
  var
    I, l, n: Integer;
    C: Char;
  begin
    Result := False;
    s := Trim(s);
    l := Length(s);
    I := 1;
    while I <= l do
    begin
      C := s[I];
      Inc(I);
      if (I <= l) and (s[I] in ['1' .. '9']) then
      begin
        n := ord(s[I]) - 48;
        Inc(I);
      end
      else
      begin
        n := 1;
      end;
      case C of
        's':
          if n > Part.Special then
            Part.Special := n;
      else
        Exit;
      end;
    end;
    Result := true;
  end;

begin
  Result := False;

  Part.Special := 0;
  SetLength(Part.Subnets, 0);
  SetLength(Part.IP, 0);

  List := TStringList.Create;
  List2 := TStringList.Create;
  try
    Data := Trim(Data);
    Explode(':', Data, List);
    if (List.Count < 1) or (List.Count > 3) then
      Exit;
    for I := 0 to List.Count - 2 do
    begin
      s := Trim(List[I]);
      if s = '' then
        Continue;
      if s[1] in ['a' .. 'z'] then
      begin
        if not ProcessFlags(s) then
          Exit;
      end
      else
      begin
        Explode(',', s, List2);
        if List2.Count < 1 then
          Exit;
        SetLength(Part.Subnets, List2.Count);
        for J := 0 to List2.Count - 1 do
        begin
          Part.Subnets[J] := Trim(List2[J]);
        end;
      end;
    end;

    s := List[List.Count - 1];
    Explode(',', s, List2);
    if List2.Count < 1 then
      Exit;

    SetLength(Part.IP, List2.Count);
    for J := 0 to List2.Count - 1 do
    begin
      Part.IP[J] := StrToIP(Trim(List2[J]));
      if Part.IP[J] = 0 then
        Exit;
    end;
    Result := true;
  finally
    List.Free;
    List2.Free;
  end;
end;

function StringToServerAddr(Data: string): TServerAddr;
var
  SL: TStringList;
  Part: TServerAddrPart;
  I, l, n, SpecialIndex, SubnetIndex: Integer;
  B: Boolean;
  SA: TServerAddr;
begin
  Data := AnsiLowerCase(Data);
  SL := TStringList.Create;
  try
    Explode(';', Data, SL);
    if SL.Count > 0 then
    begin
      for I := 0 to SL.Count - 1 do
      begin
        if StringToServerAddrPart(SL[I], Part) then
        begin
          n := Length(SA);
          SetLength(SA, n + 1);
          SA[n] := Part;
        end;
      end;
    end;
  finally
    SL.Free;
  end;

  B := False;
  for I := 0 to High(SA) do
  begin
    Part := SA[I];
    if (Part.Special < 1) and (Length(Part.Subnets) = 0) then
    begin
      B := true;
      Break;
    end;
  end;
  if not B then
  begin
    Part.Special := 0;
    SetLength(Part.Subnets, 0);
    SetLength(Part.IP, 1);
    Part.IP[0] := StrToIP('127.0.0.1');
    n := Length(SA);
    SetLength(SA, n + 1);
    SA[n] := Part;
  end;

  SetLength(Result, Length(SA));
  n := 0;

  for SpecialIndex := 9 downto 0 do
  begin
    for SubnetIndex := 1 downto 0 do
    begin
      for I := 0 to High(SA) do
      begin
        if SA[I].Special <> SpecialIndex then
          Continue;

        l := Length(SA[I].Subnets);
        if ((SubnetIndex = 1) and (l = 0)) or ((SubnetIndex = 0) and (l > 0))
        then
          Continue;

        Result[n] := SA[I];
        Inc(n);

        if (SpecialIndex = 0) AND (SubnetIndex = 0) then
          Break;
      end;
    end;
  end;

  SetLength(Result, n);
end;

function ServerAddrToString(Addr: TServerAddr): string;
var
  I, J: Integer;
  s, Part: string;
begin
  s := '';
  for I := 0 to High(Addr) do
  begin
    if s <> '' then
      s := s + '; ';

    Part := '';
    if Addr[I].Special > 0 then
    begin
      Part := Part + 's';
      if Addr[I].Special > 1 then
        Part := Part + IntToStr(Addr[I].Special);
    end;
    if Part <> '' then
      Part := Part + ':';

    if Length(Addr[I].Subnets) > 0 then
    begin
      for J := 0 to High(Addr[I].Subnets) do
      begin
        if J > 0 then
          Part := Part + ',';
        Part := Part + Addr[I].Subnets[J];
      end;
      Part := Part + ':';
    end;

    for J := 0 to High(Addr[I].IP) do
    begin
      if J > 0 then
        Part := Part + ',';
      Part := Part + IPToStr(Addr[I].IP[J]);
    end;

    s := s + Part;
  end;
  Result := s;
end;

function SelectIPFromServerAddr(Addr: TServerAddr; IP: string;
  Special: byte): Integer;
var
  I, J: Integer;
  B: Boolean;
begin
  Result := 0;
  for I := 0 to High(Addr) do
  begin
    if (Special < Addr[I].Special) then
      Continue;
    if Length(Addr[I].Subnets) > 0 then
    begin
      B := False;
      for J := 0 to High(Addr[I].Subnets) do
      begin
        if MatchesMask(IP, Addr[I].Subnets[J]) then
        begin
          B := true;
          Break;
        end;
      end;
      if not B then
        Continue;
    end;
    if Length(Addr[I].IP) > 0 then
    begin
      J := Random(Length(Addr[I].IP));
      Result := Addr[I].IP[J];
      Exit;
    end;
  end;
end;

procedure InitLog(var l: TLog; name: string);
begin
  if not l.Enabled then
    Exit;
  l.filename := path + 'log\' + name + '\' + FormatDateTime('yyyy-mm-dd',
    Now) + '.txt';
  if not DirectoryExists(ExtractFilePath(l.filename)) then
    mkdir(ExtractFilePath(l.filename));

  AssignFile(l.f, l.filename);
{$I-}
  Append(l.f);
{$I+}
  If IOResult <> 0 then
    Rewrite(l.f);
  CloseFile(l.f);
end;

function md5(s: string): string;
begin
  Result := AnsiLowerCase(md5str(md5string(s)));
end;

function CheckCRC(crc: Integer; original: string): Boolean;
var
  s: string;
begin
  Result := False;
  if original = '' then
  begin
    Result := true;
    Exit;
  end;
  s := IntToHex(crc, 8);
  if Pos(s, original) > 0 then
    Result := true;
end;

function MyMatchesMask(IP, mask: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  if mask = '' then
    Exit;
  repeat
    I := Pos(',', mask);
    if I > 0 then
    begin
      Result := Result or MatchesMask(IP, Trim(Copy(mask, 1, I - 1)));
      Delete(mask, 1, I);
    end;
  until I = 0;
  Result := Result or MatchesMask(IP, Trim(mask));
end;

function crypt(Password: string): string;
var
  I, J: Integer;
  s: string;
begin
  s := md5(Password) + md5(g.ext.md5password);
  J := 1;
  for I := 1 to Length(s) do
  begin
    if J > Length(g.ext.md5password) then
      J := 1;
    s[I] := chr(ord(s[I]) xor ord(g.ext.md5password[J]));
    J := J + 1;
  end;
  Result := md5(s);
end;

procedure EIF(msg: string; code: Integer = 0);
begin
  ATL('Error in function ''' + msg + ''' #' + IntToStr(code), mtError);
end;

function CheckTimer(var t: TMyTimer; new: Boolean = False): Boolean;
begin
  Result := False;
  if new then
  begin
    t.Enabled := true;
    t.Next := GetTickCount;
  end;
  if t.Interval = 0 then
    t.Enabled := False;
  if not t.Enabled then
    Exit;
  if (GetTickCount > t.Next) or new then
  begin
    Result := true;
    t.Next := t.Next + t.Interval * 1000;
  end;
end;

procedure AddToBlack(d: TClient);
var
  f: TextFile;
  B: Boolean;
  s: string;
  I: Integer;
begin
  try
    B := true;
    AssignFile(f, path + 'Black_hKeys.txt');
    Reset(f);
    while not EOF(f) do
    begin
      ReadLn(f, s);
      I := Pos(';', s);
      if I <> 0 then
        Delete(s, I, Length(s) - I + 1);
      s := AnsiLowerCase(Trim(s));
      if s = d.Guard.hKey then
      begin
        B := False;
        Break;
      end;
    end;
    CloseFile(f);
    if B then
    begin
      AssignFile(f, path + 'Black_hKeys.txt');
      Append(f);
      WriteLn(f, d.Guard.hKey + ' ; ID=' + d.Account + ', IP=' + d.IP + ' (' +
        DateTimeToStr(Now) + ')');
      CloseFile(f);
      ATL('New black hKey ' + d.Guard.hKey, mtInfo);
    end;
  except
    EIF('AddToBlack');
  end;
end;

function GetFullFileVersion: string;
Var
  J, w: Cardinal;
  s: shortstring;
  Buf: pointer;
  buf2: pointer;
  q: DWord;
  vsinfo: ^VS_FIXEDFILEINFO;
  mVer, lVer, rVer, bVer, flag: DWord;
begin
  s := ParamStr(0) + #0;
  J := GetFileVersionInfoSize(@s[1], w);
  if J = 0 then
    Exit;
  Buf := Ptr(GlobalAlloc(GMEM_FIXED, J));
  GetFileVersionInfo(@s[1], 0, J, Buf);
  VerQueryValue(Buf, '\', buf2, q);
  vsinfo := buf2;
  mVer := vsinfo^.dwProductVersionMS div $FFFF;
  lVer := vsinfo^.dwProductVersionMS mod $10000;
  rVer := vsinfo^.dwProductVersionLS div $FFFF;
  bVer := vsinfo^.dwProductVersionLS mod $10000;
  flag := vsinfo^.dwFileFlags;
  s := IntToStr(mVer) + '.' + IntToStr(lVer) + '.' + IntToStr(rVer) + '.' +
    IntToStr(bVer);
  if (flag and VS_FF_DEBUG) > 0 then
    s := s + ' debug ';
  if (flag and VS_FF_PRERELEASE) > 0 then
    s := s + ' prerelease ';
  if (flag and VS_FF_PRIVATEBUILD) > 0 then
    s := s + ' private ';
  if (flag and VS_FF_SPECIALBUILD) > 0 then
    s := s + ' special ';
  Result := s;
  GlobalFree(Cardinal(Buf));
end;

function EncryptPassword(str: string): string;
var
  key, dst: array [1 .. 16] of byte;
  I: Integer;
  l, l1, l2, l3, l4: int64;
  md5: TMD5Digest;
begin
  Result := '';
  if g.adv.md5simple then
  begin
    md5 := md5string(str);
    for I := 0 to 15 do
      Result := Result + chr(md5.v[I]);
    Exit;
  end;
  if g.adv.sha1 then
  begin
    Result := SHA1DigestAsString(CalcSHA1(str));
    Exit;
  end;
  try
    while Length(str) <> 16 do
      str := str + #0;
    for I := 1 to 16 do
    begin
      key[I] := ord(str[I]);
      dst[I] := key[I];
    end;
    l := 0;
    move(key[1], l, 4);
    l1 := (l * 213119 + 2529077) mod $100000000;
    move(key[5], l, 4);
    l2 := (l * 213247 + 2529089) mod $100000000;
    move(key[9], l, 4);
    l3 := (l * 213203 + 2529589) mod $100000000;
    move(key[13], l, 4);
    l4 := (l * 213821 + 2529997) mod $100000000;

    move(l1, key[1], 4);
    move(l2, key[5], 4);
    move(l3, key[9], 4);
    move(l4, key[13], 4);

    dst[1] := dst[1] xor key[1];

    for I := 2 to 16 do
      dst[I] := dst[I] xor dst[I - 1] xor key[I];
    for I := 1 to 16 do
      if dst[I] = 0 then
        dst[I] := 102;
    Result := '';
    for I := 1 to 16 do
      Result := Result + chr(dst[I]);
  except
    EIF('EncryptPassword');
  end;
end;

function GetSockError(ErrorCode: Integer): string;
begin
  case ErrorCode Of
    10004:
      Result := 'Interrupted Function call';
    10013:
      Result := 'Permission Refusee';
    10014:
      Result := 'Mauvaise adresse';
    10022:
      Result := 'Arguments Invalides';
    10024:
      Result := 'Trop de fichiers ouverts';
    10035:
      Result := 'Resource temporarily unavailable';
    10036:
      Result := 'Operation en cours';
    10037:
      Result := 'Operation deja en cours';
    10038:
      Result := 'Socket operation On non-socket';
    10039:
      Result := 'Destination address required';
    10040:
      Result := 'Message trop long';
    10041:
      Result := 'Protocol wrong Type For socket';
    10042:
      Result := 'Bad protocol option';
    10043:
      Result := 'Protocol Not supported';
    10044:
      Result := 'Socket Type Not supported';
    10045:
      Result := 'Operation Not supported';
    10046:
      Result := 'Protocol family Not supported';
    10047:
      Result := 'Address family Not supported by protocol family';
    10048:
      Result := 'Address already in use';
    10049:
      Result := 'Cannot assign requested address';
    10050:
      Result := 'Network Is down';
    10051:
      Result := 'Network Is unreachable';
    10052:
      Result := 'Network dropped connection On reset';
    10053:
      Result := 'Software caused connection abort';
    10054:
      Result := 'Connection reset by peer';
    10055:
      Result := 'No buffer space available';
    10056:
      Result := 'Socket Is already connected';
    10057:
      Result := 'Socket Is Not connected';
    10058:
      Result := 'Cannot send after socket shutdown';
    10060:
      Result := 'Connection timed Out';
    10061:
      Result := 'Connection refused';
    10064:
      Result := 'Host Is down';
    10065:
      Result := 'No route To host';
    10067:
      Result := 'Too many processes';
    10091:
      Result := 'Network subsystem Is unavailable';
    10092:
      Result := 'WINSOCK.DLL version Out Of range';
    10093:
      Result := 'Successful WSAStartup Not yet performed';
    10094:
      Result := 'Graceful shutdown In progress';
    11001:
      Result := 'Host Not found';
    11002:
      Result := 'Non-authoritative host Not found';
    11003:
      Result := 'This Is a non-recoverable error';
    11004:
      Result := 'Valid name, no data Record Of requested Type';
  else
    Result := 'Unknown socket error';
  end;
  Result := AnsiLowerCase(Result) + ' (' + IntToStr(ErrorCode) + ')';
end;

function StrToHex(s: string; Space: Boolean = False): string;
var
  I: Integer;
begin
  Result := '';
  for I := 1 to Length(s) do
  begin
    if Space then
    begin
      if Result <> '' then
        Result := Result + ' ';
    end;
    Result := Result + IntToHex(ord(s[I]), 2);
  end;
  if not Space then
    Result := AnsiLowerCase(Result);
end;

function HexToText(s: string): string;
var
  e: Boolean;
  t1, t2: string;
  I: Integer;
begin
  Result := '';
  e := False;
  t1 := '';
  for I := 1 to Length(s) do
  begin
    if (s[I] in ['0' .. '9', 'A' .. 'F', 'a' .. 'f']) then
      t1 := t1 + s[I]
    else if not(s[I] in [' ', #13, #10]) then
      e := true;
  end;
  if Length(t1) mod 2 <> 0 then
    e := true;
  if e then
    Exit;
  t2 := '';
  for I := 1 to (Length(t1) div 2) do
    t2 := t2 + chr(StrToInt('$' + t1[I * 2 - 1] + t1[I * 2]));
  Result := t2;
end;

procedure LoadOptions(Silent: Boolean = False);
var
  s: string;
  f: TextFile;
  I: Integer;

  procedure ReadFile(name: string; List: TStrings; Silent: Boolean = False);
  begin
    List.Clear;
    AssignFile(f, name);
{$I-}
    Reset(f);
{$I+}
    If IOResult = 0 then
    begin
      while not EOF(f) do
      begin
        ReadLn(f, s);
        I := Pos(';', s);
        if I <> 0 then
          Delete(s, I, Length(s) - I + 1);
        s := AnsiLowerCase(Trim(s));
        if s <> '' then
          List.Add(s);
      end;
      CloseFile(f);
      if not Silent then
        ATL('Loaded: ''' + ExtractFileName(name) + '''', mtInfo);
    end
    else
    begin
      if not Silent then
        ATL('File not found: ''' + ExtractFileName(name) + '''', mtError);
    end;
  end;

begin
  ReadFile(path + 'Black_IPs.txt', Black_IPs, Silent);
  if g.ext.Guard then
  begin
    ReadFile(path + 'Black_hKeys.txt', Black_hKeys, Silent);
    ReadFile(path + 'White_IDs.txt', White_IDs, Silent);
  end;
  ReadFile(path + 'Test_IDs.txt', Test_IDs, Silent or (not g.adv.test));
end;

function ScrambleRSA(key: string): string;
var
  k: array [0 .. 127] of byte;
  I: Integer;
  temp: byte;
begin
  if Length(key) <> 128 then
    Exit;
  for I := 0 to 127 do
    k[I] := ord(key[I + 1]);
  // step 1 : $4d-$50 <-> $00-$04
  for I := 0 to 3 do
  begin
    temp := k[$00 + I];
    k[$00 + I] := k[$4D + I];
    k[$4D + I] := temp;
  end;
  // step 2 : xor first $40 bytes with  last $40 bytes
  for I := 0 to $40 - 1 do
  begin
    k[I] := k[I] xor k[$40 + I];
  end;
  // step 3 : xor bytes $0d-$10 with bytes $34-$38
  for I := 0 to 3 do
  begin
    k[$0D + I] := k[$0D + I] xor k[$34 + I];
  end;
  // step 4 : xor last $40 bytes with  first $40 bytes
  for I := 0 to $40 - 1 do
  begin
    k[$40 + I] := k[$40 + I] xor k[I];
  end;
  Result := '';
  for I := 0 to 127 do
    Result := Result + chr(k[I]);
end;

function RSAGenerateKeys(var PrivateKey: pRSA; var PublicKey: string;
  Len: Integer = 1024): Boolean;
var
  I, l: Integer;
  M: array [0 .. 1023] of byte;
begin
  Result := False;
  if Len mod 8 <> 0 then
    Exit;
  l := Len div 8;
  if l < 8 then
    Exit;

  PrivateKey := RSA_generate_key(Len, 65537, nil, nil);
  for I := 0 to High(M) do
    M[I] := 0;
  BN_bn2bin(RSA(PrivateKey^).e, @M[0]);

  PublicKey := '';
  for I := 1 to l do
    PublicKey := PublicKey + chr(M[I - 1]);
  Result := true;
end;

procedure ATL(Text: string; MsgType: TMsgType = mtDefault;
  Color: TColor = clBlack);
var
  r: TRichEdit;
  year, month, day: word;

  procedure Insert(const Text: string; Color: TColor);
  begin
    r.SelStart := r.GetTextLen;
    r.SelLength := 0;
    r.SelAttributes.Color := Color;
    r.SelText := Text;
  end;

  procedure WTL(l: TLog);
  begin
    Append(l.f);
    try
      WriteLn(l.f, FormatDateTime('dd.mm.yyyy hh:mm:ss', Now), ': ', Text);
    finally
      CloseFile(l.f);
    end;
  end;

begin
  try
    case MsgType of
      mtError:
        Color := clRed;
      mtFunc:
        Color := clGreen;
      mtInfo:
        Color := clBlue;
      mtUser:
        Color := clBlack;
      mtWelcome:
        Color := clPurple;
      mtServer:
        Color := clGreen;
      mtGuard, mtGuardNotice:
        Color := $000080FF;
    end;

    DecodeDate(Now, year, month, day);
    if day <> LastDay then
    begin
      LastDay := day;
      InitLog(g.log.auth, 'auth');
      InitLog(g.log.Guard, 'guard');
      InitLog(g.log.all, 'all');
    end;
    if g.log.all.Enabled then
      WTL(g.log.all);
    if g.log.auth.Enabled then
      if (MsgType = mtUser) or (MsgType = mtWelcome) then
        WTL(g.log.auth);
    if g.log.Guard.Enabled then
      if (MsgType = mtGuard) or (MsgType = mtWelcome) then
        WTL(g.log.Guard);

    r := frmMain.reLog;
    if r.Lines.Count > 500 then
      r.Lines.Clear;
    Insert(FormatDateTime('[hh:mm:ss] ', Now), clBlack);
    Insert(Text + #13#10, Color);
    r.Perform(WM_VSCROLL, 1, 0);
  except
  end;
end;

function InitXOR(s: string): string;
var
  I, key, B: Integer;
begin
  try
    key := Random($FFFFFFFF);
    I := 5;
    while I < Length(s) do
    begin
      move(s[I], B, 4);
      key := key + B;
      B := B xor key;
      move(B, s[I], 4);
      I := I + 4;
    end;
    Result := s;
  except
    EIF('InitXOR');
  end;
end;

procedure WriteH(var Pck: string; v: Integer; ind: Integer = 0);
var
  a: array [1 .. 2] of Char;
begin
  a[1] := chr(v mod 256);
  a[2] := chr(v div 256);
  if ind = 0 then
  begin
    Pck := Pck + a[1] + a[2];
  end
  else if Length(Pck) >= ind + 1 then
  begin
    Pck[ind] := a[1];
    Pck[ind + 1] := a[2];
  end;
end;

procedure WriteD(var Pck: string; v: Integer; ind: Integer = 0);
var
  ab: array [1 .. 4] of Char;
  ai: Integer absolute ab;
  I: Integer;
begin
  ai := v;
  if ind = 0 then
  begin
    for I := 1 to 4 do
      Pck := Pck + ab[I];
  end
  else if Length(Pck) >= ind + 3 then
  begin
    for I := 1 to 4 do
      Pck[ind + I - 1] := ab[I];
  end;
end;

procedure WriteC(var Pck: string; v: byte; ind: Integer = 0);
begin
  if ind = 0 then
    Pck := Pck + chr(v)
  else if Length(Pck) >= ind then
    Pck[ind] := chr(v);
end;

procedure s2c(Pck: string; n: Integer; Recv: Boolean = true;
  blowfish: Boolean = true; crc: Boolean = true);
var
  I, l, X, Y: Integer;
  Buf: array [0 .. $FF] of byte;
begin
  try
    if Length(Pck) = 0 then
      Exit;

    if crc or blowfish then
    begin
      l := Length(Pck) mod 8;
      if l <> 0 then
        for I := 1 to 8 - l do
          Pck := Pck + #0;
    end;

    if crc then
    begin
      X := 0;
      for I := 0 to (Length(Pck) div 4) - 1 do
      begin
        move(Pck[I * 4], Y, 4);
        X := X xor Y;
      end;
      Pck := Pck + #0#0#0#0#0#0#0#0;
      move(X, Pck[Length(Pck) - 7], 4);
    end;

    if g.Debug then
      frmDebug.Print(Pck, 'hAuthD -> Client');

    if blowfish then
    begin
      Pck := EncryptedString(Pck, MainBlowfishKey);
      if Length(Pck) = 0 then
        Exit;
    end;

    l := Length(Pck) + 2;
    Pck := chr(l mod 256) + chr(l div 256) + Pck;
    if l > Length(Buf) then
      ATL('l>length(buf) [s2c]', mtError)
    else
    begin
      move(Pck[1], Buf[0], l);
      if cs[n].active then
        send(cs[n].sock, Buf, l, 0);
    end;
    cs[n].d.Recv.Enabled := Recv;
  except
    EIF('s2c');
  end;
end;

function PrepairPacketForL2J(Pck: string): string;
var
  I, n, X, Y: Integer;
begin
  Pck := Pck + #0#0#0#0;
  n := Length(Pck) mod 8;
  if n > 0 then
  begin
    for I := n to 8 - 1 do
      Pck := Pck + #0;
  end;

  X := 0;
  I := 1;
  n := Length(Pck) - 4;
  while I <= n do
  begin
    move(Pck[I], Y, 4);
    X := X xor Y;
    Inc(I, 4);
  end;
  move(X, Pck[Length(Pck) - 3], 4);

  Result := Pck;
end;

procedure s2s(Pck: string; ServerIndex: Integer);
var
  l, n: Integer;
  Buf: array [0 .. $FFF] of byte;
begin
  if Length(Pck) = 0 then
    Exit;

  if ServerIndex > Length(Servers) - 1 then
  begin
    ATL('Invalid Server Index', mtError);
    Exit;
  end;

  if Servers[ServerIndex].l2j then
  begin
    Pck := PrepairPacketForL2J(Pck);
    Pck := EncryptedString(Pck, Servers[ServerIndex].BlowfishKey);
  end;

  Pck := #0#0 + Pck;
  l := Length(Pck);
  Pck[1] := chr(l mod 256);
  Pck[2] := chr(l div 256);

  n := Servers[ServerIndex].index;
  if n <> -1 then
  begin
    if ss[n].active then
    begin
      move(Pck[1], Buf[0], l);
      if send(ss[n].sock, Buf, l, 0) = SOCKET_ERROR then
      begin
        ATL('Send returned SOCKET_ERROR', mtError);
      end;
    end;
  end;
end;

function ReplaceInvalidCharacters(s: string): string;
var
  I: Integer;
  B: byte;
begin
  for I := 1 to Length(s) do
  begin
    B := ord(s[I]);
    if not((B >= 32) and (B <= 126) and (B <> 39) and (B <> 96)) then
      s[I] := '?';
  end;
  Result := s;
end;

begin
  title := 'hAuthD by Hint (' + GetFullFileVersion + ')';

end.
