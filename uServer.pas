unit uServer;

interface

uses SysUtils, Windows, Messages, WinSock, uFunc, Classes;

procedure ServerThread;

implementation

uses uMain;

procedure ServerThread;
var
  Addr: TSockAddr;
  Data: TWSAData;
  Len, i, j, k, Size: Integer;
  FDSetR: TFDSet;
  LastMsg: TDateTime;
  ok: boolean;
  SelectTimeOut: TTimeVal;
  BigTimeOut, FirstTimeOut, SmallTimeOut, AntiDosEnd: TDateTime;
  tmp: string;
  LastTick: cardinal;
  buf: array [0 .. $FFFF] of byte;
  dos: boolean;
  aggr: TStrings;

  procedure KickS(i: Integer);
  begin
    if ss[i].active then
      SendMessage(frmMain.Handle, WM_SERVER_MSG, M_Disconnect, i);
    CloseSocket(ss[i].sock);
    ss[i].active := false;
  end;

  procedure KickC(i: Integer);
  begin
    if cs[i].active then
      SendMessage(frmMain.Handle, WM_SERVEREX_MSG, M_Disconnect, i);
    CloseSocket(cs[i].sock);
    cs[i].active := false;
  end;

  procedure InitTimeout(dos: boolean = false);
  begin
    if not dos then
    begin
      BigTimeOut := EncodeTime(0, 0, 15, 0);
      FirstTimeOut := EncodeTime(0, 0, 5, 0);
      SmallTimeOut := EncodeTime(0, 0, 3, 0);
    end
    else
    begin
      BigTimeOut := EncodeTime(0, 0, 7, 0);
      FirstTimeOut := EncodeTime(0, 0, 2, 0);
      SmallTimeOut := EncodeTime(0, 0, 1, 0);
    end;
  end;

begin
  try
    WSAStartup($101, Data);

    for i := 0 to High(ss) do
    begin
      ss[i].active := false;
      ss[i].kill := false;
      ss[i].d.index := -1;
    end;
    ss[0].sock := Socket(AF_Inet, Sock_Stream, 0);
    ss[0].active := true;

    Addr.sin_family := AF_Inet;
    Addr.sin_port := HToNS(g.ServerPort);
    Addr.sin_addr.S_addr := InAddr_Any;
    FillChar(Addr.Sin_Zero, SizeOf(Addr.Sin_Zero), 0);
    if Bind(ss[0].sock, Addr, SizeOf(TSockAddr)) = SOCKET_ERROR then
    begin
      SendMessage(frmMain.Handle, WM_SERVER_MSG, M_SOCKETERROR,
        WSAGetLastError);
      exit;
    end;
    Listen(ss[0].sock, SoMaxConn);
    SendMessage(frmMain.Handle, WM_SERVER_MSG, M_SERVERLISTEN, 0);

    for i := 0 to High(cs) do
    begin
      cs[i].active := false;
      cs[i].kill := false;
    end;
    cs[0].sock := Socket(AF_Inet, Sock_Stream, 0);
    cs[0].active := true;

    Addr.sin_family := AF_Inet;
    Addr.sin_port := HToNS(g.serverExPort);
    Addr.sin_addr.S_addr := InAddr_Any;
    FillChar(Addr.Sin_Zero, SizeOf(Addr.Sin_Zero), 0);
    if Bind(cs[0].sock, Addr, SizeOf(TSockAddr)) = SOCKET_ERROR then
    begin
      SendMessage(frmMain.Handle, WM_SERVEREX_MSG, M_SOCKETERROR,
        WSAGetLastError);
      exit;
    end;
    Listen(cs[0].sock, SoMaxConn);
    SendMessage(frmMain.Handle, WM_SERVEREX_MSG, M_SERVERLISTEN, 0);

    aggr := TStringList.Create;
    SelectTimeOut.tv_sec := 1;
    SelectTimeOut.tv_usec := 0;
    dos := false;
    AntiDosEnd := now;
    InitTimeout(false);

    LastMsg := now;
    LastTick := GetTickCount;
    while true do
    begin
      if g.closed then
        exit;
      if GetTickCount - LastTick > 10000 then
      begin
        LastTick := GetTickCount;
        SendMessage(frmMain.Handle, WM_THREAD_MSG, M_TIMER, 0);
        if dos then
        begin
          if now > AntiDosEnd then
          begin
            dos := false;
            InitTimeout(false);
          end;
        end;
      end;
      for i := 1 to High(cs) do
        if cs[i].active then
        begin
          if cs[i].kill then
            KickC(i)
          else
          begin
            if cs[i].d.recv.enabled then
            begin
              if cs[i].OnlyConnect then
              begin
                if now - cs[i].time > FirstTimeOut then
                  KickC(i);
              end
              else
              begin
                if now - cs[i].time > BigTimeOut then
                  KickC(i);
              end;
            end
            else
            begin
              if now - cs[i].time > SmallTimeOut then
                KickC(i);
            end;
          end;
        end;
      for i := 1 to High(ss) do
        if ss[i].active then
          if ss[i].kill then
            KickS(i);
      FD_Zero(FDSetR);
      for i := 0 to High(cs) do
        if cs[i].active then
          FD_Set(cs[i].sock, FDSetR);
      for i := 0 to High(ss) do
        if ss[i].active then
          FD_Set(ss[i].sock, FDSetR);
      Select(0, @FDSetR, nil, nil, @SelectTimeOut);
      for i := 1 to High(cs) do
        if cs[i].active then
          if FD_IsSet(cs[i].sock, FDSetR) then
          begin
            if not cs[i].d.recv.enabled then
              KickC(i)
            else
            begin
              cs[i].time := now;
              Size := recv(cs[i].sock, buf[0], Length(buf), 0);
              if Size <= 0 then
                KickC(i)
              else
                with cs[i].d do
                begin
                  SetLength(tmp, Size);
                  Move(buf[0], tmp[1], Size);
                  recv.buf := recv.buf + tmp;
                  if cs[i].OnlyConnect and cs[i].Proxy and (not cs[i].RealIP)
                  then
                  begin
                    if Length(recv.buf) > 2 then
                    begin
                      Size := ord(recv.buf[1]) + ord(recv.buf[2]) * 256;
                      if (Size = 6) and (Length(recv.buf) >= Size) then
                      begin
                        Move(recv.buf[3], k, 4);
                        cs[i].d.ip := IPToStr(k);
                        delete(recv.buf, 1, 6);
                        cs[i].RealIP := true;
                      end;
                    end;
                  end;
                  if Length(recv.buf) > 2 then
                  begin
                    Size := ord(recv.buf[1]) + ord(recv.buf[2]) * 256;
                    if Size = Length(recv.buf) then
                    begin
                      recv.pck := recv.buf;
                      recv.buf := '';
                      recv.enabled := false;
                      cs[i].OnlyConnect := false;
                      SendMessage(frmMain.Handle, WM_SERVEREX_MSG, M_Packet, i);
                    end
                    else
                    begin
                      if (Size < Length(recv.buf)) or (Size > 255) then
                      begin
                        if cs[i].OnlyConnect and g.adv.antidos and
                          (not cs[i].Proxy) then
                        begin
                          if aggr.IndexOf(cs[i].d.ip) = -1 then
                          begin
                            aggr.Add(cs[i].d.ip);
                            SendMessage(frmMain.Handle, WM_SERVEREX_MSG,
                              M_BlackIP, i);
                          end;
                        end;
                        KickC(i);
                      end;
                    end;
                  end;
                end;
            end;
          end;

      if FD_IsSet(cs[0].sock, FDSetR) then
        for i := 1 to High(cs) do
          if not cs[i].active then
          begin
            Len := SizeOf(TSockAddr);
            cs[i].sock := Accept(cs[0].sock, @Addr, @Len);
            cs[i].d.Addr := Addr;
            cs[i].d.ip := inet_ntoa(Addr.sin_addr);
            ok := true;
            if not g.enabled then
            begin
              ok := false;
              KickC(i);
            end;
            cs[i].Proxy := MyMatchesMask(cs[i].d.ip, g.adv.Proxy);
            cs[i].RealIP := not cs[i].Proxy;
            if not cs[i].Proxy then
            begin
              if ok then
                if aggr.IndexOf(cs[i].d.ip) <> -1 then
                begin
                  ok := false;
                  KickC(i);
                end;
              if ok then
                for j := 0 to Black_IPs.Count - 1 do
                begin
                  if MyMatchesMask(cs[i].d.ip, Black_IPs[j]) then
                  begin
                    ok := false;
                    if now - LastMsg > SmallTimeOut then
                    begin
                      SendMessage(frmMain.Handle, WM_SERVEREX_MSG,
                        M_BlackIP, i);
                      LastMsg := now;
                    end;
                    KickC(i);
                    break;
                  end;
                end;
              if ok then
              begin
                k := 0;
                for j := 1 to High(cs) do
                  if cs[j].active then
                    if cs[j].d.ip = cs[i].d.ip then
                      k := k + 1;
                if (k >= g.adv.MaxConnectionsPerIP) or (dos and (k > 0)) then
                begin
                  ok := false;
                  if now - LastMsg > SmallTimeOut then
                  begin
                    if not dos then
                      SendMessage(frmMain.Handle, WM_SERVEREX_MSG,
                        M_MaxConnPerIP, i);
                    LastMsg := now;
                  end;
                  KickC(i);
                end;
              end;
            end;
            if ok then
            begin
              cs[i].d.LoginOK := false;
              cs[i].time := now;
              cs[i].kill := false;
              cs[i].d.recv.enabled := false;
              cs[i].d.recv.buf := '';
              cs[i].d.recv.pck := '';
              cs[i].active := true;
              cs[i].OnlyConnect := true;
              SendMessage(frmMain.Handle, WM_SERVEREX_MSG, M_Connect, i);
            end;
            break;
          end
          else if i = High(cs) then
          begin
            if (not dos) and (g.adv.antidos) then
            begin
              dos := true;
              InitTimeout(true);
              AntiDosEnd := now + EncodeTime(0, 5, 0, 0);
              SendMessage(frmMain.Handle, WM_SERVEREX_MSG, M_ANTIDOS, 1);
            end;
          end;
      for i := 1 to High(ss) do
        if ss[i].active then
        begin
          if FD_IsSet(ss[i].sock, FDSetR) then
          begin
            Size := recv(ss[i].sock, buf[0], Length(buf), 0);
            if Size <= 0 then
              KickS(i)
            else
              with ss[i].d do
              begin
                SetLength(tmp, Size);
                Move(buf[0], tmp[1], Size);
                recv.buf := recv.buf + tmp;
                while Length(recv.buf) > 2 do
                begin
                  Size := ord(recv.buf[1]) + ord(recv.buf[2]) * 256;
                  if Length(recv.buf) < Size then
                    break;
                  recv.pck := copy(recv.buf, 1, Size);
                  delete(recv.buf, 1, Size);
                  SendMessage(frmMain.Handle, WM_SERVER_MSG, M_Packet, i);
                end;
              end;
          end;
        end;
      if FD_IsSet(ss[0].sock, FDSetR) then
        for i := 1 to High(ss) do
          if not ss[i].active then
          begin
            Len := SizeOf(TSockAddr);
            ss[i].sock := Accept(ss[0].sock, @Addr, @Len);
            ss[i].d.ip := inet_ntoa(Addr.sin_addr);
            ok := true;
            if ok then
            begin
              ss[i].kill := false;
              ss[i].d.recv.buf := '';
              ss[i].d.recv.pck := '';
              ss[i].d.index := -1;
              ss[i].active := true;
              SendMessage(frmMain.Handle, WM_SERVER_MSG, M_Connect, i);
            end;
            break;
          end;
    end;
  except
    SendMessage(frmMain.Handle, WM_THREAD_MSG, M_EXCEPT, 0);
  end;
end;

end.
