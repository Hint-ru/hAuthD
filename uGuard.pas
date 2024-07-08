unit uGuard;

interface

uses SysUtils, Windows, Messages, Classes, uTwoFish;

function GuardViewPacket(pck: string; n: integer): string;
function GuardCheckUser(n: integer): boolean;

var
  TFData: TTwofishData;

const
  TFKey: PChar = '[;$.]94-31==-%&@!^+]';

implementation

uses uMain, uDebug, uFunc;

function GuardCheckUser(n: integer): boolean;
var
  i: integer;

  procedure msg(s: string; hkey: boolean = true; notice: boolean = false);
  var
    mt: TMsgType;
  begin
    if notice then
      mt := mtGuardNotice
    else
      mt := mtGuard;
    if hkey then
      ATL(s + ' (ID=' + cs[n].d.account + ', IP=' + cs[n].d.ip + ', hKey=' +
        cs[n].d.guard.hkey + ')', mt)
    else
      ATL(s + ' (ID=' + cs[n].d.account + ', IP=' + cs[n].d.ip + ')', mt);
  end;

begin
  result := false;
  try
    with cs[n] do
    begin
      d.guard.cheat := 0;
      if not d.guard.pck then
      begin
        msg('Unprotected', false, true);
        if (g.guard.Mode = 0) or (White_IDs.IndexOf(d.account) <> -1) then
          result := true;
        exit;
      end;
      d.trader := false;
      if d.guard.error then
      begin
        msg('Hack attempt', false);
        if Hot_IDs.IndexOf(d.account) = -1 then
          Hot_IDs.Add(d.account);
        exit;
      end;
      if (g.guard.TraderCRC <> '') and CheckCRC(d.guard.ClientCRC,
        g.guard.TraderCRC) then
      begin
        msg('Trader', true, true);
        d.trader := true;
      end
      else
      begin
        if not CheckCRC(d.guard.ClientCRC, g.guard.ClientCRC) then
        begin
          msg('Modified client - ' + IntToHex(d.guard.ClientCRC, 8),
            true, true);
          exit;
        end;
      end;
      if not CheckCRC(d.guard.GuardCRC, g.guard.GuardCRC) then
      begin
        msg('Modified guard - ' + IntToHex(d.guard.GuardCRC, 8));
        exit;
      end;

      if d.guard.inf[3] <> 0 then
        d.guard.inf[2] := 0;

      if d.guard.inf[1] <> 0 then
        d.guard.inf[11] := 0;

      for i := 1 to length(d.guard.inf) - 1 do
      begin
        if d.guard.inf[i] <> 0 then
        begin
          case i of
            1:
              msg('Wicked Patcher', true, (g.cheats[i] < 0));
            2:
              msg('L2Walker', true, (g.cheats[i] < 0));
            3:
              msg('L2Walker IG', true, (g.cheats[i] < 0));
            4:
              msg('L2.net', true, (g.cheats[i] < 0));
            5:
              msg('Dead thread', true, (g.cheats[i] < 0));
            6:
              msg('MiniProxer', true, (g.cheats[i] < 0));
            7:
              msg('L2Control', true, (g.cheats[i] < 0));
            8:
              msg('Blocked explorer', true, (g.cheats[i] < 0));
            9:
              msg('L2PacketHack', true, (g.cheats[i] < 0));
            10:
              msg('WinAPI Hack', true, (g.cheats[i] < 0));
            11:
              msg('Wicked Patcher Ports', true, (g.cheats[i] < 0));
            12:
              msg('L2Walker VerifyServer Ports', true, (g.cheats[i] < 0));
            13:
              msg('Fake Login Server Ports', true, (g.cheats[i] < 0));
            14:
              msg('Hooked Game', true, (g.cheats[i] < 0));
            15:
              msg('ZRanger', true, (g.cheats[i] < 0));
          else
            msg('Cheat #' + IntToStr(i));
          end;
          if g.cheats[i] > 0 then
          begin
            if i <> 8 then
              d.guard.cheat := d.guard.cheat + g.cheats[i];
          end;
        end;
      end;
      if d.guard.cheat <> 0 then
      begin
        cheats := cheats + d.guard.cheat;
        frmMain.sb.Panels[3].Text := 'Cheats: ' + IntToStr(cheats);
        if g.guard.Mode = 2 then
        begin
          if Hot_hKeys.IndexOf(d.guard.hkey) = -1 then
          begin
            Hot_hKeys.Add(d.guard.hkey);
            if g.guard.HotToBlack then
              AddToBlack(d);
          end;
          exit;
        end;
      end;
      if (d.guard.inf[8] <> 0) and (g.cheats[8] > 0) then
        exit;

      if (((d.guard.inf[0] = 0) and g.guard.OldWithoutClient) or
        ((d.guard.inf[0] < 100) and (not g.guard.OldWithoutClient))) and
        (not d.trader) then
      begin
        msg('Without client');
        exit;
      end;
      if d.guard.inf[0] > 100 then
        d.guard.inf[0] := d.guard.inf[0] - 100;

      if d.trader and (g.guard.TraderAdv = 2) and (not d.TraderAdv) then
      begin
        msg('TraderAdv expired', true, true);
        exit;
      end;
      if g.guard.MaxWin <> 0 then
      begin
        if d.guard.inf[0] > g.guard.MaxWin then
        begin
          msg('Too many clients', true, true);
          exit;
        end;
        if g.guard.hMaxWin then
        begin
          if frmMain.QuerySelect
            ('SELECT COUNT(*) FROM user_account WHERE hkey=''%s'' AND last_ip=''%s'' AND last_login>last_logout AND account<>''%s''',
            [d.guard.hkey, d.ip, d.account]) then
            if frmMain.ADO.Fields[0].AsInteger >= g.guard.MaxWin then
            begin
              msg('Too many clients', true, true);
              exit;
            end;
        end;
      end;
      if Black_hKeys.IndexOf(d.guard.hkey) <> -1 then
      begin
        msg('Black hKey', true, true);
        exit;
      end;
      if Hot_hKeys.IndexOf(d.guard.hkey) <> -1 then
      begin
        msg('Hot hKey', true, true);
        exit;
      end;
      if Hot_IDs.IndexOf(d.account) <> -1 then
      begin
        msg('Hot ID', true, true);
        exit;
      end;
      result := true;
    end;
  except
    EIF('GuardCheckUser');
  end;
end;

function GuardViewPacket(pck: string; n: integer): string;
var
  size: word;
  i, AuthCRC, PckCRC, GuardCRC, crc: integer;
  g: TGuard;
  pi: ^integer;
  hkey: int64;
  buf: array [0 .. 47] of byte;
  function GetCRC(s: string): integer;
  var
    i, n: integer;
  begin
    result := 0;
    for i := 0 to (length(s) div 4) - 1 do
    begin
      move(s[i * 4 + 1], n, 4);
      result := result xor n;
    end;
  end;

begin
  cs[n].d.guard.pck := true;
  cs[n].d.guard.error := true;
  try
    move(pck[4], size, 2);
    result := copy(pck, 4, size);
    AuthCRC := GetCRC(copy(pck, 6, size - 2));
    PckCRC := GetCRC(copy(pck, 3, 1 + size + 32));
    move(pck[4 + size], buf[0], 48);
    pi := @buf;
    TwofishDecryptECB(TFData, pi, pi);
    inc(pi, 4);
    TwofishDecryptECB(TFData, pi, pi);
    inc(pi, 4);
    TwofishDecryptECB(TFData, pi, pi);
    for i := 0 to 7 do
    begin
      move(buf[i * 4], crc, 4);
      crc := crc xor AuthCRC;
      move(crc, buf[i * 4], 4);
    end;
    SetLength(pck, 32);
    move(buf[0], pck[1], 32);
    GuardCRC := GetCRC(pck);
    move(buf[32], crc, 4);
    if crc <> AuthCRC then
      exit;
    move(buf[36], crc, 4);
    if crc <> GuardCRC then
      exit;
    move(buf[40], crc, 4);
    if crc <> PckCRC then
      exit;
    move(buf[44], crc, 4);
    if crc <> 0 then
      exit;
    move(buf[0], g.ClientCRC, 4);
    move(buf[4], g.GuardCRC, 4);
    move(buf[8], hkey, 8);
    g.hkey := AnsiLowerCase(IntToHex(hkey, 16));
    move(buf[16], g.inf[0], 16);
    g.error := false;
    g.pck := true;
    cs[n].d.guard := g;
  except
    EIF('GuardViewPacket');
  end;
end;

begin
  TwofishInit(TFData, TFKey, Sizeof(TFKey), nil);

end.
