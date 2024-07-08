unit uMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, WinSock, StdCtrls, ComCtrls, XPMan, uFunc, libeay32, uBlowFish,
  Menus, ShellApi, ADODB, IniFiles, DB, uServer, uGuard, uAntiBrute, ExtCtrls,
  uAuthKeys, uUsers, cHash;

const
  WM_SERVEREX_MSG = WM_USER + 1;
  WM_SERVER_MSG = WM_USER + 2;
  WM_THREAD_MSG = WM_USER + 3;

  M_CONNECT = 1;
  M_DISCONNECT = 2;
  M_PACKET = 3;
  M_MAXCONNPERIP = 4;
  M_BLACKIP = 5;
  M_SERVERLISTEN = 6;
  M_SOCKETERROR = 7;
  M_READY = 8;
  M_ANTIDOS = 9;
  M_EXCEPT = 10;
  M_TIMER = 11;
  M_DEBUG = 12;

type
  TAuthResult = (arSuccess, arPassword, arBanned, arInuse, arFailed, arBrute,
    arMask, arTest, arGuard, arHBind, arExecLogin);

  TServer = record
    Index: Integer;
    IP: string;

    Recv: record
      Buf: string;
      Pck: string;
    end;
  end;

  TGameServer = record
    Id: Byte;
    Name: string;
    Addr: TServerAddr;
    Port: Integer;
    InnerIP: string;
    MasterId: Integer;
    Test: Boolean;
    OnlineMultiplier: Double;
    Index: Integer;
    MasterIndex: Integer;
    L2J: Boolean;
    Cur, Max: Integer;
    BlowfishKey: TBlowfishKey;
  end;

  PGameServer = ^TGameServer;

type
  TfrmMain = class(TForm)
    reLog: TRichEdit;
    XPManifest: TXPManifest;
    MainMenu: TMainMenu;
    Log1: TMenuItem;
    mi_LAuth: TMenuItem;
    Clear1: TMenuItem;
    Options1: TMenuItem;
    opt_black_ips: TMenuItem;
    opt_black_hkeys: TMenuItem;
    N1: TMenuItem;
    Reload: TMenuItem;
    N2: TMenuItem;
    ADOConnection: TADOConnection;
    ADO: TADODataSet;
    miServer: TMenuItem;
    miTestIDs: TMenuItem;
    miServerGroup: TMenuItem;
    opt_white_ids: TMenuItem;
    mi_LGuard: TMenuItem;
    sb: TStatusBar;
    miCheaters: TMenuItem;
    miShow: TMenuItem;
    miBlock: TMenuItem;
    mi_Hot: TMenuItem;
    mi_hot_hkeys: TMenuItem;
    mi_hot_ids: TMenuItem;
    N3: TMenuItem;
    Forgiveall1: TMenuItem;
    mi_LAll: TMenuItem;
    N4: TMenuItem;
    mi_Debug: TMenuItem;
    N5: TMenuItem;
    miOptions: TMenuItem;
    miTestMode: TMenuItem;
    Homepage1: TMenuItem;
    Homepage2: TMenuItem;
    miReloadWorlds: TMenuItem;
    Workingdirectory1: TMenuItem;
    N6: TMenuItem;
    procedure ClientConnect(n: Integer);
    procedure ClientDisconnect(n: Integer);
    procedure ClientPacket(n: Integer);
    procedure ServerConnect(n: Integer);
    procedure ServerDisconnect(n: Integer);
    procedure ServerPacket(n: Integer);
    procedure FormCreate(Sender: TObject);
    function CheckUser(n: Integer): TAuthResult;
    procedure Clear1Click(Sender: TObject);
    procedure ReloadClick(Sender: TObject);
    procedure opt_black_ipsClick(Sender: TObject);
    procedure opt_black_hkeysClick(Sender: TObject);
    procedure mi_LAuthClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure miServerClick(Sender: TObject);
    procedure miTestIDsClick(Sender: TObject);
    procedure opt_white_idsClick(Sender: TObject);
    procedure mi_LGuardClick(Sender: TObject);
    procedure ShowUsers;
    procedure ShowServers;
    procedure LoadServers(Silent: Boolean = False);
    procedure PrintServer(Server: TGameServer);
    procedure miShowClick(Sender: TObject);
    procedure miBlockClick(Sender: TObject);
    function QuerySelect(sql: string; args: array of const): Boolean;
    function QueryUpdate(sql: string; args: array of const;
      msg: Boolean = False; text: string = ''): Integer;
    function QueryInsert(sql: string; args: array of const): Integer;
    procedure Timer;
    procedure mi_hot_hkeysClick(Sender: TObject);
    procedure mi_hot_idsClick(Sender: TObject);
    procedure Forgiveall1Click(Sender: TObject);
    procedure mi_LAllClick(Sender: TObject);
    procedure mi_DebugClick(Sender: TObject);
    procedure miTestModeClick(Sender: TObject);
    procedure miOptionsClick(Sender: TObject);
    procedure Options1Click(Sender: TObject);
    procedure ProcessPlayOk(ClientIndex: Integer; ServerId: Integer;
      Key: Integer);
    procedure Homepage2Click(Sender: TObject);
    procedure miReloadWorldsClick(Sender: TObject);
    procedure Workingdirectory1Click(Sender: TObject);

  private
    { Private declarations }
    procedure ServerExMessage(var msg: TMessage); message WM_SERVEREX_MSG;
    procedure ServerMessage(var msg: TMessage); message WM_SERVER_MSG;
    procedure ThreadMessage(var msg: TMessage); message WM_THREAD_MSG;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;
  ServerTID: Cardinal;
  TestServers: string;
  ss: array [0 .. 7] of record
    sock: TSocket;
    d: TServer;
    active: Boolean;
    kill: Boolean;
  end;
  cs: array [0 .. 55] of record
    sock: TSocket;
    d: TClient;
    active: Boolean;
    kill: Boolean;
    time: TDateTime;
    OnlyConnect: Boolean;
    Proxy: Boolean;
    RealIP: Boolean;
  end;
  Servers: array of TGameServer;
  AuthKeys: TAuthKeys;
  TestServersAmount: Integer;
  g: record
    Debug: Boolean;
    Cheats: array [1 .. 15] of Integer;
    Closed: Boolean;
    ServerPort: Integer;
    ServerExPort: Integer;
    Title: string;
    Tables: record
      Server: string;
    end;
    L2J: record
      IP: string;
      Protocol: Integer;
      FixedPorts: Boolean;
    end;
    Online: record
      Multiplier: Double;
    end;
    Guard: record
      ClientCRC, GuardCRC, TraderCRC: string;
      TraderAdv: Integer;
      Mode: Integer;
      MaxWin: Integer;
      hMaxWin: Boolean;
      cheaters: Integer;
      HotToBlack: Boolean;
      OldWithoutClient: Boolean;
    end;
    enabled: Boolean;
    BFstatic: string;
    BFtemp: string;
    SQL: record
      user, password, server, database: string;
      SlowQuery: Integer;
    end;
    log: record
      auth, guard, all: TLog;
      db: Boolean;
    end;
    Adv: record
      EULA: Boolean;
      Test: Boolean;
      C4: Boolean;
      C1Msg: Boolean;
      MaxConnectionsPerIP: Integer;
      proxy: string;
      freeguard: Boolean;
      antidos: Boolean;
      AntiBrute, AntiBruteIP: Boolean;
      md5simple: Boolean;
      sha1: Boolean;
      LRKey: Boolean;
      GameProxyMasterStatus: Boolean;
    end;
    ext: record
      mask, hbind, guard, ExecLogin: Boolean;
      md5password: string;
    end;
    admin: record
      password: string;
      ip: string;
    end;
    RSA: record
      PrivateKey: pRSA;
      PublicKey, ScrambledPublicKey: string;
      L2JPrivate: pRSA;
      L2JPublic: string;
    end;
  end;
  path: string;
  sql: record
    select, login, logout, logout_without_id, guard: string;
  end;
  Black_IPs, Black_hKeys, Hot_hKeys, Hot_IDs, Test_IDs, White_IDs: TStrings;
  StartTime: cardinal;
  Timers: record
    Online, Autoban, UserCount, ReloadFiles, ReloadServers, Reconnect: TMyTimer;
  end;
  served: Integer;
  cheats: Integer;
  tick: cardinal;
  AntiBrute, AntiBruteIP: TAntiBrute;
  MainBlowfishKey: TBlowfishKey;
  AuthUsers: TAuthUsers;

implementation

uses uDebug;

{$R *.dfm}

function GetServerIndexById(Id: Integer): Integer;
var
  I: Integer;
begin
  for I := 0 to High(Servers) do
  begin
    if Servers[I].Id = Id then
    begin
      Result := I;
      Exit;
    end;
  end;
  Result := -1;
end;

function GetActiveServerIndex(SI: Integer): Integer;
begin
  if (SI < 0) or (SI > High(Servers)) then
  begin
    SI := -1;
  end
  else
  begin
    if (Servers[SI].MasterIndex >= 0) then
    begin
      if g.Adv.GameProxyMasterStatus or (Servers[SI].Index >= 0) then
      begin
        SI := Servers[SI].MasterIndex;
      end
      else
      begin
        SI := -1;
      end;
    end;
    if SI >= 0 then
    begin
      if Servers[SI].Index < 0 then
        SI := -1;
    end;
  end;
  Result := SI;
end;

procedure TfrmMain.PrintServer(Server: TGameServer);
var
  S: string;
begin
  S := Format('Server #%d: Name = [%s], IP = [%s], Inner IP = [%s], Port = %d',
    [Server.Id, Server.Name, ServerAddrToString(Server.Addr), Server.InnerIP,
    Server.Port]);
  if Server.MasterIndex >= 0 then
    S := S + Format(', Master = %d', [Server.MasterId]);
  ATL(S, mtServer);
end;

procedure ProcessMasterIds;
var
  I, J: Integer;
  Id: Integer;
begin
  for I := 0 to High(Servers) do
  begin
    Servers[I].MasterIndex := -1;

    Id := Servers[I].MasterId;
    if Id > 0 then
    begin
      for J := 0 to High(Servers) do
      begin
        if (Id = Servers[J].Id) and (I <> J) then
        begin
          Servers[I].MasterIndex := J;
          Break;
        end;
      end;
    end;
  end;
end;

procedure TfrmMain.LoadServers(Silent: Boolean = False);
var
  I, MI, n, Id: Integer;
  F: Double;
  Server: TGameServer;
  Update: Boolean;
  S: string;
begin
  Update := Length(Servers) > 0;

  if not QuerySelect('SELECT * FROM dbo.' + g.Tables.Server, []) then
    Exit;
  if ADO.IsEmpty then
    Exit;

  while not ADO.Eof do
  begin
    Id := ADO.FieldByName('id').AsInteger;
    if Update then
    begin
      I := GetServerIndexById(Id);
    end
    else
    begin
      I := Length(Servers);
      SetLength(Servers, I + 1);
    end;

    if I >= 0 then
    begin
      Server := Servers[I];

      if not Update then
      begin
        Server.Id := Id;

        if ADO.FindField('master_id') = nil then
          MI := 0
        else
          MI := ADO.FieldByName('master_id').AsInteger;
        Server.MasterId := MI;

        Server.Test := False;
        if ADO.FieldByName('kind').AsInteger = 16 then
          Server.Test := True;
        if Pos(',' + IntToStr(Id) + ',', TestServers) <> 0 then
          Server.Test := True;

        Server.Index := -1;
        Server.Cur := 0;
        Server.Max := 0;
      end;

      S := ReplaceInvalidCharacters(Trim(ADO.FieldByName('name').AsString));
      if S = '' then
        S := 'Unknown';
      Server.Name := S;

      Server.Addr := StringToServerAddr(ADO.FieldByName('ip').AsString);
      Server.Port := ADO.FieldByName('port').AsInteger;
      Server.InnerIP := ADO.FieldByName('inner_ip').AsString;

      if ADO.FindField('online_multiplier') = nil then
        F := 1
      else
        F := ADO.FieldByName('online_multiplier').AsFloat;
      Server.OnlineMultiplier := F;

      Servers[I] := Server;
    end;

    ADO.Next;
  end;
  ADO.Close;

  if not Update then
  begin
    ProcessMasterIds;

    n := 0;
    for I := 0 to High(Servers) do
    begin
      MI := Servers[I].MasterIndex;
      if MI >= 0 then
        Servers[I].Test := Servers[MI].Test;
      if Servers[I].Test then
        Inc(n);
    end;
    TestServersAmount := n;
  end;

  if not Silent then
  begin
    for I := 0 to High(Servers) do
    begin
      PrintServer(Servers[I]);
    end;
  end;
end;

procedure TfrmMain.Timer;
var
  dif: Cardinal;
  m, h, d: Integer;
  S: string;
  I: Integer;
begin
  if CheckTimer(Timers.Reconnect) then
  begin
    ADO.Connection.Close;
    if QuerySelect('SELECT GETDATE()', []) then
      Timers.Reconnect.enabled := False;
  end;

  if CheckTimer(Timers.Autoban) then
    miBlockClick(nil);
  if CheckTimer(Timers.Online) then
  begin
    for I := 0 to High(Servers) do
    begin
      if Servers[I].Index <> -1 then
      begin
        if Servers[I].L2J then
        begin
          Servers[I].Cur := AuthUsers.GetCount(Servers[I].Id);
        end
        else
        begin
          s2s(#2, I);
        end;
      end;
    end;
  end;
  if CheckTimer(Timers.UserCount) then
  begin
    for I := 0 to High(Servers) do
    begin
      QueryInsert
        ('INSERT INTO dbo.user_count (record_time,server_id,world_user,limit_user,auth_user,wait_user,dayofweek) VALUES (GETDATE(),%d,%d,%d,%d,0,DATEPART(dw,GETDATE()))',
        [Servers[I].Id, Servers[I].Cur, Servers[I].Max, Servers[I].Cur]);
    end;
  end;

  if CheckTimer(Timers.ReloadFiles) then
    LoadOptions(True);
  if CheckTimer(Timers.ReloadServers) then
    LoadServers(True);

  dif := (GetTickCount - StartTime) div 60000;
  d := dif div 1440;
  m := dif mod 60;
  h := (dif mod 1440) div 60;
  S := IntToStr(d) + ' d ';
  if h < 10 then
    S := S + '0';
  S := S + IntToStr(h) + ' h ';
  if m < 10 then
    S := S + '0';
  S := S + IntToStr(m) + ' m ';
  sb.panels[0].text := 'Uptime: ' + S;
end;

procedure ShowSlowQuery(Elapsed: Integer; const sql: string);
var
  S: string;
begin
  if g.sql.SlowQuery < 1 then
    Exit;
  if Elapsed < g.sql.SlowQuery then
    Exit;
  S := Format('Slow query: %d ms!', [Elapsed]);
  if sql <> '' then
    S := S + ' ' + sql;
  ATL(S, mtError);
end;

function TfrmMain.QuerySelect(sql: string; args: array of const): Boolean;
var
  tick: Cardinal;
begin
  Result := False;
  sql := Format(sql, args);
  ADO.Close;
  try
    tick := GetTickCount;
    ADO.CommandText := sql;
    ADO.Open;
    tick := GetTickCount - tick;
    ShowSlowQuery(tick, sql);
  except
    on E: Exception do
    begin
      ATL(E.Message, mtError);
      if not Timers.Reconnect.enabled then
        CheckTimer(Timers.Reconnect, True);
      Exit;
    end;
  end;
  Result := True;
end;

function TfrmMain.QueryInsert(sql: string; args: array of const): Integer;
var
  I: Integer;
  tick: Cardinal;
begin
  try
    tick := GetTickCount;
    sql := Format(sql, args);
    I := 0;
    ADOConnection.Execute(sql, I);
    Result := I;
    tick := GetTickCount - tick;
    ShowSlowQuery(tick, 'INSERT ...');
  except
    on E: Exception do
    begin
      ATL(E.Message, mtError);
      Result := 0;
    end;
  end;
end;

function TfrmMain.QueryUpdate(sql: string; args: array of const;
  msg: Boolean = False; text: string = ''): Integer;
var
  I: Integer;
  S: string;
  tick: Cardinal;
begin
  Result := 0;
  sql := Format(sql, args);
  I := 0;

  try
    tick := GetTickCount;
    ADOConnection.Execute(sql, I);
    tick := GetTickCount - tick;
    if not msg then
      ShowSlowQuery(tick, sql);
  except
    on E: Exception do
    begin
      ATL(E.Message, mtError);
      Exit;
    end;
  end;

  if msg then
  begin
    S := Format('%d row(s) affected', [I]);
    if text <> '' then
      S := text + ': ' + S;
    ATL(S, mtInfo);
  end;

  Result := I;
end;

procedure TfrmMain.ShowServers;
var
  I, n: Integer;
begin
  n := 0;
  for I := 0 to Length(Servers) - 1 do
    if Servers[I].Index <> -1 then
      n := n + 1;
  sb.panels[1].text := 'Servers: ' + IntToStr(n);
end;

procedure TfrmMain.ShowUsers;
begin
  sb.panels[2].text := 'Users: ' + IntToStr(AuthUsers.GetCount);
end;

procedure TfrmMain.ClientConnect(n: Integer);
var
  tmp: string;
begin
  try
    served := served + 1;
    sb.panels[4].text := 'Served: ' + IntToStr(served);
    with cs[n] do
    begin
      d.account := '';
      d.password := '';
      d.sid := random($FFFFFFFF);
      d.LastID := $FF;
      d.Guard.Pck := False;
      d.Guard.error := False;
      d.Guard.cheat := 0;
      d.Guard.hkey := '';
      d.tick := GetTickCount;
      d.SpecialGates := 0;
      d.Tester := False;
    end;
    tmp := #0;
    WriteD(tmp, cs[n].d.sid);
    WriteD(tmp, $0000C621);
    tmp := tmp + g.RSA.ScrambledPublicKey + #0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0;
    if not g.Adv.C4 then
    begin
      tmp := tmp + g.BFtemp + #0#0#0#0#0#0#0#0#0#0#0#0#0#0#0;
      tmp := InitXOR(tmp);
    end;
    s2c(tmp, n, True, not g.Adv.C4, False);
  except
    EIF('ClientConnect');
  end;
end;

procedure TfrmMain.ClientDisconnect(n: Integer);
begin
  if g.Debug then
    ATL('Client.Tick: ' + IntToStr(GetTickCount - cs[n].d.tick));
end;

function TfrmMain.CheckUser(n: Integer): TAuthResult;
var
  I: Integer;
  tmp: string;
  adm: Boolean;
  AuthOk: Boolean;
  S: string;
  DT: TDateTime;
  AntiBruteID: string;
begin
  Result := arFailed;
  try
    with cs[n] do
    begin
      adm := False;
      if (d.account = '') or (d.password = '') then
      begin
        Result := arPassword;
        Exit;
      end;
      for I := 1 to High(cs) do
        if cs[I].active then
          if cs[I].d.LoginOK then
            if (cs[I].d.account = d.account) and (cs[I].d.password = d.password)
            then
            begin
              Result := arInuse;
              Exit;
            end;
      AntiBruteID := d.account + '-' + d.IP;

      if g.Adv.AntiBrute then
      begin
        if AntiBrute.IsBrute(AntiBruteID) then
        begin
          Result := arBrute;
          Exit;
        end;
      end;
      if g.Adv.AntiBruteIP then
      begin
        if AntiBruteIP.IsBrute(d.IP) then
        begin
          Result := arBrute;
          Exit;
        end;
      end;

      if not QuerySelect(sql.select, [d.account]) then
      begin
        Result := arFailed;
        Exit;
      end;
      if ADO.IsEmpty then
      begin
        Result := arPassword;
        if g.Adv.AntiBruteIP then
          AntiBruteIP.IsNewBrute(d.IP);
        Exit;
      end;

      d.LoginFlag := ADO.FieldByName('login_flag').AsInteger;
      d.WarnFlag := ADO.FieldByName('warn_flag').AsInteger;

      if ADO.FindField('premium_expire') <> nil then
      begin
        DT := ADO.FieldByName('premium_expire').AsDateTime;
        if DT <> 0 then
        begin
          if DT < Now then
          begin
            d.LoginFlag := d.LoginFlag and not(1 shl 10);
          end;
        end;
      end;

      if g.admin.password <> '' then
        if d.password = g.admin.password then
          if MyMatchesMask(d.IP, g.admin.IP) then
            adm := True;

      if ADO.FindField('special_gates') <> nil then
      begin
        I := ADO.FieldByName('special_gates').AsInteger;
        if I < 0 then
          I := 0;
        if I > 9 then
          I := 9;
        d.SpecialGates := I;
      end;

      AuthOk := (EncryptPassword(d.password) = ADO.FieldByName('password')
        .AsString);
      if g.ext.md5password <> '' then
      begin
        S := ADO.FieldByName('md5password').AsString;
        if S <> '' then
          AuthOk := (crypt(d.password) = S)
        else if AuthOk then
        begin
          QueryUpdate
            ('UPDATE user_auth SET md5password = ''%s'', password = 0 WHERE account = ''%s''',
            [crypt(d.password), d.account], False);
        end;
      end;
      if not AuthOk then
      begin
        if adm then
          ATL(d.account + ' - password (ADMIN)', mtInfo)
        else
        begin
          if g.Adv.AntiBrute then
            AntiBrute.IsNewBrute(AntiBruteID);
          if g.Adv.AntiBruteIP then
            AntiBruteIP.IsNewBrute(d.IP);
          Result := arPassword;
          Exit;
        end;
      end
      else
      begin
        if g.Adv.AntiBrute then
          AntiBrute.NotBrute(AntiBruteID);
      end;
      if (ADO.FieldByName('pay_stat').AsInteger = 0) or
        (ADO.FieldByName('block_flag').AsInteger <> 0) or
        (ADO.FieldByName('block_flag2').AsInteger <> 0) or
        (ADO.FieldByName('block_end_date').AsDateTime > Now) then
      begin
        if adm then
          ATL(d.account + ' - banned (ADMIN)', mtInfo)
        else
        begin
          Result := arBanned;
          Exit;
        end;
      end;
      if g.ext.mask then
        if ADO.FieldByName('mask').AsString <> '' then
        begin
          if not MyMatchesMask(d.IP, ADO.FieldByName('mask').AsString) then
          begin
            if adm then
              ATL(d.account + ' - mask (ADMIN)', mtInfo)
            else
            begin
              Result := arMask;
              Exit;
            end;
          end;
        end;
      if g.ext.hbind then
        if ADO.FieldByName('hbind').AsString <> '' then
        begin
          if not MyMatchesMask(d.Guard.hkey, ADO.FieldByName('hbind').AsString)
          then
          begin
            if adm then
              ATL(d.account + ' - hbind (ADMIN)', mtInfo)
            else
            begin
              Result := arHBind;
              Exit;
            end;
          end;
        end;
      if g.Adv.Test or (TestServersAmount > 0) then
      begin
        d.Tester := (d.LoginFlag = 16) or (Test_IDs.IndexOf(d.account) >= 0);
        if (g.Adv.Test or (TestServersAmount = Length(Servers))) and
          (not d.Tester) then
        begin
          if adm then
            ATL(d.account + ' - test (ADMIN)', mtInfo)
          else
          begin
            Result := arTest;
            Exit;
          end;
        end;
      end;
      d.TraderAdv := False;
      if g.Guard.TraderAdv > 0 then
        if ADO.FieldByName('adv').AsDateTime > Now then
          d.TraderAdv := True;
      d.uid := ADO.FieldByName('uid').AsInteger;
      d.LastWorld := ADO.FieldByName('last_world').AsInteger;

      I := AuthUsers.GetServerId(d.uid, d.account);
      if I >= 0 then
      begin
        Result := arInuse;
        I := GetServerIndexById(I);
        if I >= 0 then
        begin
          if Servers[I].L2J then
          begin
            tmp := #4 + StrToUni(d.account);
            s2s(tmp, I);
          end
          else
          begin
            tmp := #1;
            WriteD(tmp, d.uid);
            tmp := tmp + d.account + #0;
            s2s(tmp, I);
          end;
        end;
        Exit;
      end;

      if g.ext.Guard then
        if not GuardCheckUser(n) then
        begin
          if adm then
            ATL(d.account + ' - guard (ADMIN)', mtInfo)
          else
          begin
            Result := arGuard;
            if d.Guard.cheat > 0 then
              QueryUpdate(sql.Guard, [d.IP, d.Guard.hkey,
                d.Guard.cheat, d.uid]);
            Exit;
          end;
        end;
      if adm then
        d.Guard.cheat := 0;

      if (not d.Guard.Pck) and d.Trader then
      begin
        ATL('Trader (ID=' + d.account + ')', mtGuardNotice);
        if (g.Guard.TraderAdv = 2) and (not d.TraderAdv) then
        begin
          ATL('TraderAdv expired (ID=' + d.account + ')', mtGuardNotice);
          Result := arGuard;
          Exit;
        end;
      end;

      if g.ext.ExecLogin then
      begin
        if QuerySelect
          ('EXEC hauthd_login @uid = %d, @ip = ''%s'', @hkey = ''%s''',
          [d.uid, d.IP, d.Guard.hkey]) then
          if not ADO.IsEmpty then
            if ADO.FieldByName('ok').AsInteger = 0 then
            begin
              if adm then
                ATL(d.account + ' - ExecLogin (ADMIN)', mtInfo)
              else
              begin
                Result := arExecLogin;
                Exit;
              end;
            end;
      end;
      d.LoginOK := True;
      Result := arSuccess;
    end;
  except
    EIF('CheckUser');
  end;
end;

procedure TfrmMain.ProcessPlayOk(ClientIndex: Integer; ServerId: Integer;
  Key: Integer);
var
  S: string;
begin
  with cs[ClientIndex] do
  begin
    if d.Trader and (d.TraderAdv or (g.Guard.TraderAdv = 0)) then
    begin
      S := #$77;
      WriteD(S, d.sid xor d.uid xor $AAAAAA);
      s2c(S, ClientIndex, False);
    end;
    S := #7;
    WriteD(S, Key);
    WriteD(S, d.uid);
    s2c(S, ClientIndex, False);

    if g.ext.Guard then
    begin
      QueryUpdate(sql.login, [d.LastWorld, d.IP, d.Guard.hkey,
        d.Guard.cheat, d.uid]);
    end
    else
    begin
      QueryUpdate(sql.login, [d.LastWorld, d.IP, d.uid]);
    end;
    if g.log.DB then
      QueryInsert
        ('INSERT INTO dbo.hauthd_log (time,account,ip,hkey) VALUES (GETDATE(),''%s'',''%s'',''%s'')',
        [d.account, d.IP, d.Guard.hkey]);
  end;
end;

procedure TfrmMain.ServerPacket(n: Integer);
var
  I, Id, J, k, l, Key, AccountId, SessionId: Integer;
  tmp, Pck, S, Answer, Name: string;
  b: Boolean;
  GS: PGameServer;
  Index: Integer;

{$I read_func.inc}
  function _ReadD(var Index: Integer): Integer;
  var
    ab: array [1 .. 4] of char;
    ai: Integer absolute ab;
    I: Integer;
  begin
    if index < 1 then
      index := 1;
    Result := -1;
    if Length(Pck) < index + 3 then
      Exit;
    for I := 1 to 4 do
      ab[I] := Pck[index + I - 1];
    Result := ai;
    index := index + 4;
  end;

begin
  try
    Pck := ss[n].d.Recv.Pck;
    if Length(Pck) < 3 then
      Exit;
    if (ss[n].d.Index < Low(Servers)) or (ss[n].d.Index > High(Servers)) then
      Exit;
    GS := @Servers[ss[n].d.Index];
    if GS^.L2J then
    begin
      if (Length(Pck) - 2) mod 8 <> 0 then
        Exit;
      Pck := DecryptedString(Copy(Pck, 3, Length(Pck) - 2), GS^.BlowfishKey);
      Index := 2;
      case Ord(Pck[1]) of
        $00: // BlowfishKey
          begin
            l := ReadD;
            if l <= 0 then
              Exit;
            tmp := Copy(Pck, Index, l);

            l := RSA_size(g.RSA.L2JPrivate);
            if Length(tmp) <> l then
              Exit;
            SetLength(S, l);
            for I := 1 to Length(S) do
              S[I] := #0;
            RSA_private_decrypt(Length(tmp), PAnsiChar(tmp), PAnsiChar(S),
              g.RSA.L2JPrivate, 3);

            for I := 1 to Length(S) do
            begin
              if S[I] <> #0 then
              begin
                Delete(S, 1, I - 1);
                Break;
              end;
            end;

            GenerateSubKeys(S[1], Length(S), GS^.BlowfishKey);
          end;
        $01: // AuthRequest
          begin
            Id := ReadC; // id
            if (ReadC <> 0) then
              Id := GS^.Id; // acceptAlternate
            ReadC; // reserveHost

            if g.L2J.Protocol < $104 then
            begin
              ReadS; // externalHost
              ReadS; // internalHost
            end;

            I := ReadH; // port
            if not g.L2J.FixedPorts then
              GS^.Port := I;
            GS^.Max := ReadD; // maxPlayer

            Answer := '';
            if (Id = GS^.Id) then
            begin
              Answer := #2 + chr(Id) +
                StrToUni('#' + IntToStr(Id) + ' (hAuthD)');
              ATL('Server is successfully authorized (L2J)', mtServer);
            end
            else
            begin
              Answer := #1#4; // REASON_ID_RESERVED
              ss[n].kill := True;
            end;
            if Answer <> '' then
              s2s(Answer, ss[n].d.Index);
          end;
        $06: // ServerStatus
          begin
            // Nothing
          end;
        $05: // PlayerAuthRequest
          begin
            Name := ReadS;
            Key := ReadD; // Key
            AccountId := ReadD; // AccountId
            I := ReadD; // AccountId
            SessionId := ReadD; // SessionId

            b := AuthKeys.IsValidKeyForId(AccountId, SessionId, GS^.Id, Key);

            Answer := #3 + StrToUni(Name) + chr(Ord(b));
            s2s(Answer, ss[n].d.Index);
          end;
        $03: // PlayerLogout
          begin
            Name := ReplaceInvalidCharacters(ReadS);
            if Name <> '' then
            begin
              AuthUsers.DeleteUser(Name);
              QueryUpdate(sql.logout_without_id, [Name]);
              ShowUsers;
            end;
          end;
        $02: // PlayerInGame
          begin
            l := ReadH;
            for I := 1 to l do
            begin
              Name := ReadS;
              AuthUsers.AddUser(GS^.Id, 0, Name);
            end;
            ShowUsers;
          end;
      end;
      Exit;
    end;

    Index := 4;
    I := 4;
    with ss[n] do
      case Ord(Pck[3]) of
        $05: // Online
          begin
            if Length(Pck) = 7 then
            begin
              I := d.Index;
              if (I >= 0) and (I < Length(Servers)) then
              begin
                Servers[I].Cur :=
                  Round((Ord(Pck[4]) + Ord(Pck[5]) * 256) * g.Online.Multiplier
                  * Servers[I].OnlineMultiplier);
                Servers[I].Max := Ord(Pck[6]) + Ord(Pck[7]) * 256;
                if Servers[I].Cur > Servers[I].Max then
                  Servers[I].Max := Servers[I].Cur;
              end;
            end;
          end;
        $0B: // Players
          begin
            k := _ReadD(I);
            for l := 1 to k do
            begin
              while Pck[I] <> #0 do
                I := I + 1;
              I := I + 1;
              AccountId := _ReadD(I);

              AuthUsers.AddUser(GS^.Id, AccountId, '');
              I := I + 16;
            end;
            tmp := #5;
            WriteD(tmp, k);
            s2s(tmp, ss[n].d.Index);
            ATL('Block with players (' + IntToStr(k) + ')', mtServer);
            ShowUsers;
          end;
        $02: // Login
          begin
            AccountId := _ReadD(I);
            AuthUsers.AddUser(GS^.Id, AccountId, '');
            ShowUsers;
          end;
        $03: // Logout
          begin
            AccountId := _ReadD(I);
            AuthUsers.DeleteUser(AccountId);
            QueryUpdate(sql.logout, [AccountId]);
            ShowUsers;
          end;
        $01: // Login Failed
          begin
            I := I + 1;
            k := _ReadD(I);
            for J := 1 to High(cs) do
              if cs[J].active then
                if cs[J].d.LoginOK then
                  if cs[J].d.uid = k then
                  begin
                    s2c(#6#1, J, False);
                    Exit;
                  end;
          end;
        $00: // Key
          begin
            k := _ReadD(I);
            Key := _ReadD(I);
            for J := 1 to High(cs) do
              if cs[J].active then
                if cs[J].d.LoginOK then
                  if cs[J].d.uid = k then
                    with cs[J] do
                    begin
                      ProcessPlayOk(J, Servers[ss[n].d.Index].Id, Key);
                      Exit;
                    end;
          end;
        $06: // block_flag
          begin
            AccountId := ReadD;
            I := ReadH;
            QueryUpdate
              ('UPDATE dbo.user_account SET block_flag = %d WHERE uid = %d',
              [I, AccountId]);
          end;
      end;
  except
    EIF('ServerPacket');
  end;
end;

procedure TfrmMain.ServerConnect(n: Integer);
var
  I, k: Integer;
  tmp: string;
  L2J: Boolean;
  S: string;
  AlreadyConnected: Boolean;
begin
  try
    L2J := MyMatchesMask(ss[n].d.IP, g.L2J.IP);

    AlreadyConnected := False;
    k := -1;
    for I := 0 to High(Servers) do
    begin
      if MyMatchesMask(ss[n].d.IP, Servers[I].InnerIP) then
      begin
        if (Servers[I].Index = -1) then
        begin
          k := I;
          Break;
        end
        else
        begin
          AlreadyConnected := True;
        end;
      end;
    end;

    S := Format('New world server connection: IP = %s, Type = ', [ss[n].d.IP]);
    if L2J then
      S := S + 'L2J'
    else
      S := S + 'PTS';
    if k >= 0 then
    begin
      S := S + ', Id = ' + IntToStr(Servers[k].Id);
      if Servers[k].MasterIndex >= 0 then
        S := S + ', Master = ' + IntToStr(Servers[k].MasterId);
      S := S + '.';
      ATL(S, mtServer);
    end
    else
    begin
      if AlreadyConnected then
        S := S + '. Already connected!'
      else
        S := S + '. Non-registered!';
      ATL(S, mtError);
      ss[n].kill := True;
      Exit;
    end;

    ss[n].d.Index := k;
    Servers[k].Index := n;
    Servers[k].L2J := L2J;
    Servers[k].Cur := 0;
    Servers[k].Max := 5000;

    if L2J then
    begin
      tmp := '_;v.]05-31!|+-%xT!^[$' + #0;
      GenerateSubKeys(tmp[1], Length(tmp), Servers[k].BlowfishKey);

      tmp := #0;
      WriteD(tmp, g.L2J.Protocol);
      WriteD(tmp, Length(g.RSA.L2JPublic) + 1);
      tmp := tmp + #0 + g.RSA.L2JPublic;
      s2s(tmp, k);
    end
    else
    begin
      tmp := #$03;
      WriteD(tmp, 40504);
      WriteD(tmp, 1);
      s2s(tmp, k);
    end;

    ShowServers;
  except
    EIF('ServerConnect');
  end;
end;

procedure TfrmMain.ServerDisconnect(n: Integer);
var
  SI, I: Integer;
  S: string;
begin
  try
    ATL('Close connection from ' + ss[n].d.IP, mtError);
    SI := ss[n].d.Index;
    if (SI >= Low(Servers)) and (SI <= High(Servers)) then
    begin
      if Servers[SI].MasterIndex = -1 then
      begin
        AuthUsers.DeleteUsers(Servers[SI].Id);

        S := IntToStr(Servers[SI].Id);
        for I := 0 to High(Servers) do
        begin
          if Servers[I].MasterIndex = SI then
          begin
            S := S + ', ' + IntToStr(Servers[I].Id);
          end;
        end;

        S := 'UPDATE dbo.user_account SET last_logout = GETDATE() WHERE last_login > last_logout AND last_world IN ('
          + S + ')';
        QueryUpdate(S, []);

        Servers[SI].Index := -1;
        Servers[SI].Cur := 0;
        Servers[SI].Max := 0;
        ShowUsers;
        ShowServers;
      end;
    end;
  except
    EIF('ServerDisconnect');
  end;
end;

function DecodeLRData(Data: string): string;
var
  Key: Byte;
  A, b, I, l: Integer;
begin
  Result := '';

  l := Length(Data) - 4;
  if l < 160 then
    Exit;

  Key := l mod 255;
  for I := 1 to l do
  begin
    Data[I] := chr(Ord(Data[I]) xor Key);
    if (I mod 2 = 0) then
      Inc(Key, 34)
    else
      Inc(Key, 75);
  end;

  A := 1;
  b := 0;
  for I := 1 to l do
  begin
    A := (A + Ord(Data[I])) mod 65521;
    b := (b + A) mod 65521;
  end;
  A := (b shl 16) or A;
  Move(Data[l + 1], b, 4);
  if A <> b then
    Exit;

  Result := Data;
end;

procedure TfrmMain.ClientPacket(n: Integer);
var
  I, J, k, Key: Integer;
  Pck, tmp, Block: string;
  SI: Integer;
  AR: TAuthResult;
  S: string;

  function ReadD(var Index: Integer): Integer;
  begin
    if Index < 1 then
      Index := 1;
    if Length(Pck) < Index + 3 then
    begin
      Result := -1;
      Exit;
    end;
    Move(Pck[Index], Result, 4);
    Inc(Index, 4);
  end;

  procedure SendServerList(n: Integer);
  var
    S: string;
    I: Integer;
    ServerIP, ServerPort, SI: Integer;
    Amount: Integer;
  begin
    try
      with cs[n] do
      begin
        Amount := 0;

        S := #4;
        WriteC(S, 0);
        WriteC(S, d.LastWorld);

        for I := 0 to High(Servers) do
        begin
          if (Servers[I].Test) and (not d.Tester) then
            Continue;
          Inc(Amount);

          WriteC(S, Servers[I].Id);

          ServerIP := SelectIPFromServerAddr(Servers[I].Addr, d.IP,
            d.SpecialGates);
          ServerPort := Servers[I].Port;

          SI := GetActiveServerIndex(I);

          WriteD(S, ServerIP);
          WriteD(S, ServerPort);
          S := S + #0#0;
          if SI >= 0 then
          begin
            WriteH(S, Servers[SI].Cur);
            WriteH(S, Servers[SI].Max);
            WriteC(S, 1);
          end
          else
          begin
            WriteH(S, 0);
            WriteH(S, 0);
            WriteC(S, 0);
          end;

          WriteD(S, 0);
          WriteC(S, 0);
        end;

        WriteC(S, Amount, 2);
        s2c(S, n);
      end;
    except
      EIF('SendServerList');
    end;
  end;

begin
  try
    Pck := cs[n].d.Recv.Pck;
    if g.Debug then
      frmDebug.Print(Pck, 'Client -> hAuthD');
    if cs[n].d.LastID = $07 then
      if Length(Pck) = 255 then
        if Pck[3] = #$F0 then
          Pck := GuardViewPacket(Pck, n);
    if cs[n].d.LastID = $FF then
      if Length(Pck) = 3 then
      begin
        case Ord(Pck[3]) of
          $FF:
            s2c(#$FF + Title + #0, n, False, False, False);
          $FE:
            begin
              J := 0;
              tmp := #$FE;
              WriteH(tmp, 0);
              for I := 0 to High(Servers) do
                if Servers[I].Index <> -1 then
                begin
                  J := J + 1;
                  WriteH(tmp, Servers[I].Id);
                  WriteH(tmp, Servers[I].Cur);
                end;
              WriteH(tmp, J, 2);
              s2c(tmp, n, False, False, False);
            end;
        end;
        Exit;
      end;
    I := Length(Pck);
    if (I < 3) or ((I - 2) mod 8 <> 0) then
      Exit;
    Pck := Pck[1] + Pck[2] + DecryptedString(Copy(Pck, 3, I - 2),
      MainBlowfishKey);
    if g.Debug then
      frmDebug.Print(Pck, 'Client -> hAuthD (decrypted)');
    I := 4;
    with cs[n] do
      case Ord(Pck[3]) of
        $07:
          begin
            if d.LastID <> $FF then
            begin
              kill := True;
              Exit;
            end;
            k := ReadD(I);
            if k <> d.sid then
            begin
              kill := True;
              Exit;
            end
            else
            begin
              tmp := #$0B;
              WriteD(tmp, d.sid);
              tmp := tmp + #0#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0;
              s2c(tmp, n);
            end;
          end;
        $02:
          begin
            if (d.LastID <> $05) or (not d.LoginOK) then
            begin
              kill := True;
              Exit;
            end;
            J := ReadD(I);
            k := ReadD(I);
            if g.Adv.EULA then
            begin
              if (J <> d.uid) or (k <> d.sid) then
              begin
                kill := True;
                Exit;
              end;
            end;

            k := ReadD(I); // World
            d.LastWorld := k;

            SI := GetActiveServerIndex(GetServerIndexById(k));

            if SI < 0 then
            begin
              s2c(#6#1, n, False);
              Exit;
            end;

            if Servers[SI].L2J then
            begin
              Key := AuthKeys.NewKey(d.uid, d.account, d.sid, Servers[SI].Id);
              ProcessPlayOk(n, Servers[SI].Id, Key);
            end
            else
            begin
              // AuthRequestAboutToPlay
              S := #0;
              WriteD(S, d.uid);
              S := S + d.account + #0;
              WriteD(S, 0); // Total Time
              WriteD(S, d.LoginFlag);
              WriteD(S, d.WarnFlag);
              WriteD(S, 1); // Pay Stat
              WriteC(S, 0);
              WriteD(S, 0); // Charge Method
              WriteD(S, 0);
              WriteD(S, 0);

              S := S + '0000000' + #0;
              WriteD(S, d.Addr.sin_addr.S_addr); // IP
              WriteC(S, 0);
              WriteC(S, 0);
              WriteD(S, 0);

              s2s(S, SI);
            end;
            Exit;
          end;

        $05:
          begin
            if d.LastID <> $00 then
            begin
              kill := True;
              Exit;
            end;
            J := ReadD(I);
            k := ReadD(I);
            if (J <> d.uid) or (k <> d.sid) then
            begin
              kill := True;
              Exit;
            end;
            SendServerList(n);
          end;
        $00:
          begin
            if d.LastID <> $07 then
            begin
              if g.Adv.C4 and (d.LastID = $FF) and (Length(Pck) = 50) and g.Adv.C1Msg
              then
                ATL('Connection using old (C1) auth protocol refused (IP=' +
                  d.IP + ')', mtInfo);
              kill := True;
              Exit;
            end;

            if g.Adv.LRKey then
            begin
              if Length(Pck) < 194 then
              begin
                kill := True;
                Exit;
              end;
              tmp := DecodeLRData(Copy(Pck, 4, 164));
              if tmp = '' then
              begin
                kill := True;
                Exit;
              end;
              d.Guard.hkey := StrToHex(Copy(tmp, 1, 32));
              tmp := Copy(tmp, 33, 128);
              Inc(I, 164);
            end
            else
            begin
              if Length(Pck) < I + 128 then
              begin
                kill := True;
                Exit;
              end;
              tmp := Copy(Pck, I, 128);
              Inc(I, 128);
            end;

            k := ReadD(I);
            if k <> d.sid then
            begin
              kill := True;
              Exit;
            end
            else
            begin
              try
                SetLength(Block, 128);
                RSA_private_decrypt(128, PAnsiChar(tmp), PAnsiChar(Block),
                  g.RSA.PrivateKey, 3);
                tmp := Block;
              except
                ATL('FGIntMontgomeryModExp', mtError);
              end;
              if g.Adv.C4 then
              begin
                if (Length(tmp) < 30) then
                begin
                  kill := True;
                  ATL('Not enough data in RSA block', mtError);
                  Exit;
                end
                else
                  tmp := Copy(tmp, Length(tmp) - 29, 30);
              end
              else
              begin
                if (Length(tmp) < 34) then
                begin
                  kill := True;
                  ATL('Not not enough data in RSA block', mtError);
                  Exit;
                end
                else
                  tmp := Copy(tmp, Length(tmp) - 33, 34);
              end;
              d.account := '';
              d.password := '';

              if not d.Guard.Pck then
                if (Length(tmp) = 34) then
                  if Copy(tmp, 31, 4) = #$FF#$FF#$FF#$FF then
                    d.Trader := True;

              for J := 1 to 14 do
                if tmp[J] <> #0 then
                  d.account := d.account + tmp[J]
                else
                  Break;
              for J := 15 to 30 do
                if tmp[J] <> #0 then
                  d.password := d.password + tmp[J]
                else
                  Break;
              d.account := ReplaceInvalidCharacters
                (AnsiLowerCase(Trim(d.account)));
              d.password := Trim(d.password);

              AR := CheckUser(n);

              case AR of
                arSuccess:
                  begin
                    if d.Guard.Pck and (not d.Guard.error) then
                    begin
                      ATL(d.account + ' - success (IP=' + d.IP + ', hKey=' +
                        d.Guard.hkey + ')', mtUser);
                    end
                    else
                    begin
                      ATL(d.account + ' - success (' + d.IP + ')', mtUser);
                    end;

                    if not g.Adv.EULA then
                    begin
                      d.LastID := $05;
                      SendServerList(n);
                      Exit;
                    end
                    else
                    begin
                      tmp := #3;
                      WriteD(tmp, d.uid);
                      WriteD(tmp, d.sid);
                      tmp := tmp +
                        #0#0#0#0#0#0#0#0#1#0#0#0#0#0#0#0#0#0#0#0#0#0#0#0;
                      s2c(tmp, n);
                    end;
                  end;
                arPassword:
                  begin
                    s2c(#1#3, n, False);
                    ATL(d.account + ' - password (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arBanned:
                  begin
                    s2c(#1#19, n, False);
                    ATL(d.account + ' - banned (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arInuse:
                  begin
                    s2c(#1#7, n, False);
                    ATL(d.account + ' - in use (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arFailed:
                  begin
                    s2c(#1#1, n, False);
                    ATL(d.account + ' - failed (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arMask:
                  begin
                    s2c(#1#5, n, False);
                    ATL(d.account + ' - mask (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arHBind:
                  begin
                    s2c(#1#5, n, False);
                    ATL(d.account + ' - hbind (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arExecLogin:
                  begin
                    s2c(#1#4, n, False);
                    ATL(d.account + ' - ExecLogin (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arTest:
                  begin
                    s2c(#1#16, n, False);
                    ATL(d.account + ' - test (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arGuard:
                  begin
                    s2c(#1#4, n, False);
                    ATL(d.account + ' - guard (' + d.IP + ')', mtUser);
                    Exit;
                  end;
                arBrute:
                  begin
                    s2c(#1#1, n, False);
                    ATL(d.account + ' - antibrute (' + d.IP + ')', mtUser);
                    Exit;
                  end;
              end;
            end;
          end;
      end;
    cs[n].d.LastID := Ord(Pck[3]);
  except
    EIF('ClientPacket');
  end;
end;

procedure TfrmMain.ThreadMessage(var msg: TMessage);
begin
  try
    case msg.WParam of
      M_EXCEPT:
        EIF('ServerThread', msg.LParam);
      M_TIMER:
        Timer;
      M_DEBUG:
        ATL(Format('Debug: %d', [msg.LParam]));
    end;
  except
    EIF('ThreadMessage');
  end;
end;

procedure TfrmMain.ServerExMessage(var msg: TMessage);
begin
  try
    case msg.WParam of
      M_CONNECT:
        ClientConnect(msg.LParam);
      M_DISCONNECT:
        ClientDisconnect(msg.LParam);
      M_PACKET:
        ClientPacket(msg.LParam);
      M_MAXCONNPERIP:
        ATL('Connection refused: too many sessions for address (IP=' +
          cs[msg.LParam].d.IP + ')', mtInfo);
      M_BLACKIP:
        ATL('Connection refused: address is currently blacklisted (IP=' +
          cs[msg.LParam].d.IP + ')', mtInfo);
      M_SERVERLISTEN:
        ATL('ServerEx ready on port ' + IntToStr(g.ServerExPort), mtInfo);
      M_SOCKETERROR:
        ATL('ServerEx: ' + GetSockError(msg.LParam), mtError);
      M_ANTIDOS:
        if msg.LParam = 1 then
          ATL('Attention! AntiDOS mode!', mtError);
    end;
  except
    EIF('ServerExMessage');
  end;
end;

procedure TfrmMain.ServerMessage(var msg: TMessage);
begin
  try
    case msg.WParam of
      M_CONNECT:
        ServerConnect(msg.LParam);
      M_DISCONNECT:
        ServerDisconnect(msg.LParam);
      M_PACKET:
        ServerPacket(msg.LParam);
      M_SERVERLISTEN:
        ATL('Server ready on port ' + IntToStr(g.ServerPort), mtInfo);
      M_SOCKETERROR:
        ATL('Server: ' + GetSockError(msg.LParam), mtError);
    end;
  except
    EIF('ServerMessage');
  end;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
var
  I: Integer;
  IniFile: TIniFile;
  S: string;
  FS: TFormatSettings;
begin
  try
    served := 0;
    Cheats := 0;
    Application.Title := 'hAuthD';
    frmMain.Caption := Title;
    StartTime := GetTickCount;
    g.Debug := False;
    g.Closed := False;
    Randomize;
    path := ExtractFilePath(ParamStr(0));

    Black_IPs := TStringList.Create;
    White_IDs := TStringList.Create;
    Test_IDs := TStringList.Create;
    Black_hKeys := TStringList.Create;
    Hot_hKeys := TStringList.Create;
    Hot_IDs := TStringList.Create;

    IniFile := TIniFile.Create(path + 'hAuthD.ini');
    with IniFile do
    begin
      g.ServerPort := ReadInteger('Main', 'ServerPort', 2104);
      g.ServerExPort := ReadInteger('Main', 'ServerExPort', 2106);
      g.BFstatic := HexToText(ReadString('Main', 'BlowfishKey',
        '6B60CB5B82CE90B1CC2B6C556C6C6C6C'));
      g.Title := ReplaceInvalidCharacters(ReadString('Main', 'Title', ''));

      g.admin.password := ReadString('admin', 'password', '');
      g.admin.IP := ReadString('admin', 'ip', '*');
      g.ext.mask := ReadBool('ext', 'mask', False);
      g.ext.hbind := ReadBool('ext', 'hbind', False);
      g.ext.Guard := ReadBool('ext', 'guard', False);
      g.ext.ExecLogin := ReadBool('ext', 'ExecLogin', False);
      g.ext.md5password := ReadString('ext', 'md5password', '');
      if g.ext.md5password = '0' then
        g.ext.md5password := '';

      g.Adv.EULA := ReadBool('adv', 'eula', True);
      g.Adv.Test := ReadBool('adv', 'test', False);

      S := ReadString('adv', 'TestServers', '');
      TestServers := '';
      for I := 1 to Length(S) do
      begin
        if S[I] in ['0' .. '9', ','] then
          TestServers := TestServers + S[I];
      end;
      TestServers := ',' + TestServers + ',';

      g.Adv.C4 := ReadBool('adv', 'C4', False);
      g.Adv.C1Msg := ReadBool('adv', 'C1Msg', True);
      g.Adv.Proxy := ReadString('adv', 'proxy', '');
      g.Adv.MaxConnectionsPerIP := ReadInteger('adv', 'MaxConnectionsPerIP', 3);
      g.Adv.freeguard := ReadBool('adv', 'freeguard', False);
      g.Adv.antidos := ReadBool('adv', 'antidos', False);
      g.Adv.AntiBrute := ReadBool('adv', 'AntiBrute', False);
      g.Adv.AntiBruteIP := ReadBool('adv', 'AntiBruteIP', False);
      g.Adv.md5simple := ReadBool('adv', 'md5simple', False);
      g.Adv.sha1 := ReadBool('adv', 'sha1', False);
      g.Adv.LRKey := ReadBool('Adv', 'LRKey', False);
      g.Adv.GameProxyMasterStatus :=
        ReadBool('Adv', 'GameProxyMasterStatus', True);

      S := ReadString('L2J', 'IP', '');
      if S = '' then
        S := ReadString('Main', 'L2J', ''); // old
      S := AnsiLowerCase(S);
      if (S = '1') or (S = 'true') then
        S := '*';
      if (S = '0') or (S = 'false') then
        S := '';
      g.L2J.IP := S;
      g.L2J.Protocol := ReadInteger('L2J', 'Protocol', $103);
      g.L2J.FixedPorts := ReadBool('L2J', 'FixedPorts', True);

      g.sql.user := ReadString('mssql', 'user', 'sa');
      g.sql.password := ReadString('mssql', 'password', '');
      g.sql.Server := ReadString('mssql', 'server', '127.0.0.1');
      g.sql.database := ReadString('mssql', 'database', 'lin2db');
      g.sql.SlowQuery := ReadInteger('mssql', 'SlowQuery', 100);

      g.Tables.Server := ReplaceInvalidCharacters
        (ReadString('tables', 'server', ''));
      if g.Tables.Server = '' then
        g.Tables.Server := 'server';

      g.Guard.ClientCRC := ReadString('guard', 'ClientCRC', '');
      g.Guard.GuardCRC := ReadString('guard', 'GuardCRC', '');
      g.Guard.TraderCRC := ReadString('guard', 'TraderCRC', '');
      g.Guard.TraderAdv := ReadInteger('guard', 'TraderAdv', 0);
      g.Guard.Mode := ReadInteger('guard', 'Mode', 0);
      g.Guard.MaxWin := ReadInteger('guard', 'MaxWin', 0);
      g.Guard.hMaxWin := ReadBool('guard', 'hMaxWin', False);
      g.Guard.cheaters := ReadInteger('guard', 'cheaters', 0);
      Timers.Autoban.interval := ReadInteger('guard', 'autoban', 0) * 60;
      g.Guard.HotToBlack := ReadBool('guard', 'HotToBlack', False);
      g.Guard.OldWithoutClient := ReadBool('guard', 'OldWithoutClient', False);

      g.log.auth.enabled := ReadBool('log', 'auth', True);
      g.log.Guard.enabled := ReadBool('log', 'guard', True);
      g.log.all.enabled := ReadBool('log', 'all', False);
      g.log.DB := ReadBool('log', 'db', False);

      AntiBrute := TAntiBrute.Create;
      AntiBrute.interval := ReadInteger('AntiBrute', 'Interval', 60);
      AntiBrute.Penalty := ReadInteger('AntiBrute', 'Penalty', 180);
      AntiBrute.MaxAttempts := ReadInteger('AntiBrute', 'MaxAttempts', 5);

      AntiBruteIP := TAntiBrute.Create;
      AntiBruteIP.interval := ReadInteger('AntiBruteIP', 'Interval', 60);
      AntiBruteIP.Penalty := ReadInteger('AntiBruteIP', 'Penalty', 180);
      AntiBruteIP.MaxAttempts := ReadInteger('AntiBruteIP', 'MaxAttempts', 5);

      S := ReadString('online', 'Multiplier', '1');
      GetLocaleFormatSettings(GetThreadLocale, FS);
      FS.DecimalSeparator := '.';
      if not TryStrToFloat(S, g.Online.Multiplier, FS) then
      begin
        FS.DecimalSeparator := ',';
        if not TryStrToFloat(S, g.Online.Multiplier, FS) then
          g.Online.Multiplier := 1;
      end;

      Timers.UserCount.interval := ReadInteger('Online', 'UserCount', 0) * 60;
      Timers.Online.interval := ReadInteger('Online', 'Interval', 30);

      Timers.ReloadFiles.enabled := ReadBool('Adv', 'AutoReloadFiles', False);
      if Timers.ReloadFiles.enabled then
      begin
        Timers.ReloadFiles.interval := 90;
        CheckTimer(Timers.ReloadFiles, True);
      end;

      I := ReadInteger('Adv', 'AutoReloadServers', 0);
      if I = 1 then
        I := 90;
      Timers.ReloadServers.enabled := I > 0;
      if Timers.ReloadServers.enabled then
      begin
        Timers.ReloadServers.interval := I;
        CheckTimer(Timers.ReloadServers, True);
      end;

      for I := 1 to High(g.Cheats) do
        g.Cheats[I] := ReadInteger('cheats', IntToStr(I), 1);

      if g.ext.Guard then
        if (g.Guard.Mode < 0) or (g.Guard.Mode > 2) then
          g.Guard.Mode := 0;
      Free;
    end;

    if g.Title <> '' then
    begin
      if Length(g.Title) > 50 then
        SetLength(g.Title, 50);
      g.Title := Trim(g.Title);
      frmMain.Caption := frmMain.Caption + ' - ' + g.Title;
    end;

    AuthKeys := TAuthKeys.Create;
    AuthUsers := TAuthUsers.Create;

    if not DirectoryExists(path + 'log') then
      MkDir(path + 'log');
    ATL('Welcome to hAuthD', mtWelcome);

    mi_LAuth.Visible := g.log.auth.enabled;
    mi_LGuard.Visible := g.log.Guard.enabled;
    mi_LAll.Visible := g.log.all.enabled;

    if FileExists(path + 'lin2db.udl') then
    begin
      ADOConnection.ConnectionString := 'FILE NAME=' + path + 'lin2db.udl';
      ADOConnection.Provider := 'FILE NAME=' + path + 'lin2db.udl';
    end
    else
    begin
      ADOConnection.ConnectionString :=
        Format('Provider=SQLOLEDB.1;Password=%s;Persist Security Info=True;User ID=%s;Initial Catalog=%s;Data Source=%s',
        [g.sql.password, g.sql.user, g.sql.database, g.sql.Server]);
      ADOConnection.Provider := 'SQLOLEDB.1';
    end;

    sql.select :=
      'SELECT * FROM dbo.user_auth A INNER JOIN dbo.user_account U ON A.account = U.account WHERE U.account = ''%s''';

    if g.ext.Guard then
      sql.login :=
        'UPDATE dbo.user_account SET last_login = GETDATE(), last_world = %d, last_ip = ''%s'', hkey = ''%s'', cheat = cheat + %d WHERE uid = %d'
    else
      sql.login :=
        'UPDATE dbo.user_account SET last_login = GETDATE(), last_world = %d, last_ip = ''%s'' WHERE uid = %d';
    sql.Guard :=
      'UPDATE dbo.user_account SET last_ip = ''%s'', hkey = ''%s'', cheat = cheat + %d WHERE uid = %d';

    sql.logout :=
      'UPDATE dbo.user_account SET last_logout = GETDATE() WHERE uid = %d';
    sql.logout_without_id :=
      'UPDATE dbo.user_account SET last_logout = GETDATE() WHERE account = ''%s''';
    if not g.ext.Guard then
    begin
      opt_black_hkeys.Visible := False;
      opt_white_ids.Visible := False;
      mi_hot_hkeys.Visible := False;
      mi_hot_ids.Visible := False;
      mi_Hot.Visible := False;
    end;
    if g.Guard.Mode <> 2 then
      mi_hot_hkeys.Visible := False;
    miCheaters.Visible := ((g.Guard.cheaters > 0) and g.ext.Guard);
    LoadOptions;

    if Length(g.BFstatic) <> 16 then
      if not g.Adv.C4 then
      begin
        ATL('Blowfish key must be 16 bytes in length', mtError);
        Exit;
      end;

    GenerateSubKeys(g.BFstatic[1], Length(g.BFstatic), MainBlowfishKey);
    g.BFtemp := g.BFstatic;

    RSAGenerateKeys(g.RSA.PrivateKey, g.RSA.PublicKey, 1024);
    g.RSA.ScrambledPublicKey := ScrambleRSA(g.RSA.PublicKey);

    RSAGenerateKeys(g.RSA.L2JPrivate, g.RSA.L2JPublic, 512);

    SetLength(Servers, 0);
    LoadServers;

    if Length(Servers) = 0 then
    begin
      ATL('There are no servers in list! Check the database!', mtError);
      Exit;
    end;

    Timers.Online.enabled := False;
    Timers.Autoban.enabled := False;
    Timers.UserCount.enabled := False;
    Timers.Reconnect.enabled := False;

    Timers.Reconnect.interval := 15;

    if (Timers.Autoban.interval <> 0) and (Timers.Autoban.interval < 3600) then
    begin
      Timers.Autoban.interval := 3600;
      ATL('Attention! INI\GUARD\AUTOBAN = 60!', mtError);
    end;
    if g.Adv.md5simple and g.Adv.sha1 then
    begin
      g.Adv.sha1 := False;
      ATL('Conflicting settings: MD5simple and SHA1.');
    end;
    if g.ext.Guard and (g.Guard.cheaters > 0) then
    begin
      if CheckTimer(Timers.Autoban, True) then
        miBlockClick(nil);
    end;
    CheckTimer(Timers.Online, True);
    CheckTimer(Timers.UserCount, True);

    g.enabled := True;
    miServer.enabled := True;
    miServer.Caption := 'Disable';
    miReloadWorlds.enabled := True;
    ADO.Tag := 1;
    BeginThread(nil, 0, @ServerThread, nil, 0, ServerTID);
  except
    EIF('FormCreate');
  end;
end;

procedure TfrmMain.Clear1Click(Sender: TObject);
begin
  reLog.Clear;
end;

procedure TfrmMain.ReloadClick(Sender: TObject);
begin
  LoadOptions;
end;

procedure TfrmMain.opt_black_ipsClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(path + 'Black_IPs.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.opt_black_hkeysClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(path + 'Black_hKeys.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.mi_LAuthClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(g.log.auth.filename), nil, nil, SW_SHOW);
end;

procedure TfrmMain.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  if Application.MessageBox('Are you want quit?', 'hAuthD',
    MB_ICONQUESTION + MB_OKCANCEL) = id_OK then
  begin
    g.Closed := True;
    CanClose := True;
    try
      DeleteFile(path + 'Hot_hKeys.txt');
      DeleteFile(path + 'Hot_IDs.txt');
    except
    end;
  end
  else
    CanClose := False;
end;

procedure TfrmMain.miServerClick(Sender: TObject);
begin
  g.enabled := not g.enabled;
  if g.enabled then
  begin
    ATL('Ready to serve!', mtInfo);
    miServer.Caption := 'Disable';
  end
  else
  begin
    ATL('Attention! Now nobody can log in anymore!', mtError);
    miServer.Caption := 'Enable';
  end;
end;

procedure TfrmMain.miTestIDsClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(path + 'Test_IDs.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.opt_white_idsClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(path + 'White_IDs.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.mi_LGuardClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(g.log.Guard.filename), nil, nil, SW_SHOW);
end;

procedure TfrmMain.miShowClick(Sender: TObject);
var
  F: TextFile;
begin
  if not QuerySelect
    ('SELECT account, last_ip, cheat, hkey FROM dbo.user_account WHERE cheat >= %d AND block_flag2 = 0 ORDER BY cheat DESC',
    [g.Guard.cheaters]) then
    Exit;
  AssignFile(F, path + 'cheaters.txt');
  Rewrite(F);
  while not ADO.Eof do
  begin
    WriteLn(F, Format('%s (cheat=%d, ip=%s, hkey=%s)',
      [ADO.FieldByName('account').AsString, ADO.FieldByName('cheat').AsInteger,
      ADO.FieldByName('last_ip').AsString, ADO.FieldByName('hkey').AsString]));
    ADO.Next;
  end;
  CloseFile(F);
  ADO.Close;
  ShellExecute(0, nil, PChar(path + 'cheaters.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.miBlockClick(Sender: TObject);
begin
  QueryUpdate
    ('UPDATE dbo.user_account SET block_flag2 = 1 WHERE cheat >= %d AND block_flag2 = 0',
    [g.Guard.cheaters], True, 'Block all');
end;

procedure TfrmMain.mi_hot_hkeysClick(Sender: TObject);
begin
  Hot_hKeys.SaveToFile(path + 'Hot_hKeys.txt');
  ShellExecute(0, nil, PChar(path + 'Hot_hKeys.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.mi_hot_idsClick(Sender: TObject);
begin
  Hot_IDs.SaveToFile(path + 'Hot_IDs.txt');
  ShellExecute(0, nil, PChar(path + 'Hot_IDs.txt'), nil, nil, SW_SHOW);
end;

procedure TfrmMain.Forgiveall1Click(Sender: TObject);
begin
  QueryUpdate
    ('UPDATE dbo.user_account SET cheat = 0 WHERE cheat > 0 AND block_flag2 = 0',
    [], True, 'Forgive all');
end;

procedure TfrmMain.mi_LAllClick(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(g.log.all.filename), nil, nil, SW_SHOW);
end;

procedure TfrmMain.mi_DebugClick(Sender: TObject);
begin
  g.Debug := not g.Debug;
  mi_Debug.Checked := g.Debug;
end;

procedure TfrmMain.miTestModeClick(Sender: TObject);
begin
  g.Adv.Test := not g.Adv.Test;
end;

procedure TfrmMain.miOptionsClick(Sender: TObject);
begin
  miTestMode.Checked := g.Adv.Test;
end;

procedure TfrmMain.Options1Click(Sender: TObject);
begin
  miTestIDs.Visible := g.Adv.Test;
end;

procedure PrintList;
var
  I: Integer;
  pu: PAuthUser;
begin
  ATL('[begin]', mtServer);
  for I := 0 to AuthUsers.List.Count - 1 do
  begin
    pu := AuthUsers.List[I];
    ATL(Format('Server = %d, Id = %d, Name = %s', [pu^.ServerId, pu^.Id,
      pu^.Name]));
  end;
  ATL('[end]', mtServer);
end;

procedure TfrmMain.Homepage2Click(Sender: TObject);
begin
  ShellExecute(0, nil, 'http://hauthd.org/', nil, nil, SW_SHOW);
end;

procedure TfrmMain.miReloadWorldsClick(Sender: TObject);
begin
  LoadServers;
end;

procedure TfrmMain.Workingdirectory1Click(Sender: TObject);
begin
  ShellExecute(0, nil, PChar(path), nil, PChar(path), SW_SHOW);
end;

end.
