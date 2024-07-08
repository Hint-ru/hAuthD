unit uDebug;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls;

type
  TfrmDebug = class(TForm)
    mDebug: TMemo;
    function Print(s: string; msg: string = ''; ascii: boolean = true): string;
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmDebug: TfrmDebug;

implementation

uses uMain;

{$R *.dfm}

function TfrmDebug.Print(s: string; msg: string = '';
  ascii: boolean = true): string;
var
  i, j, k: integer;
  a: string;
  b: byte;
begin
  result := '';
  j := 0;
  for i := 1 to length(s) do
  begin
    inc(j);
    result := result + IntToHex(ord(s[i]), 2) + ' ';
    b := ord(s[i]);
    if (b < 33) or ((b > 126) and (b < 192)) or (b = ord('&')) then
      b := ord('.');
    a := a + chr(b);
    if (j = 16) or (i = length(s)) then
    begin
      if i = length(s) then
        for k := 0 to 15 - j do
          result := result + '   ';
      if ascii then
        result := result + ' | ' + a + #13#10
      else
        result := result + #13#10;
      a := '';
      j := 0;
    end;
  end;
  if msg = '' then
    msg := TimeToStr(now);
  msg := msg + ' [' + IntToStr(length(s)) + ' b' + ']';
  mDebug.Lines.Add(msg);
  mDebug.Lines.Add(result);
  if not frmDebug.Visible then
  begin
    frmDebug.Show;
    frmDebug.Left := Screen.WorkAreaWidth - frmDebug.Width;
    frmDebug.Top := 0;
    frmDebug.Height := Screen.WorkAreaHeight;
    if frmMain.Left + frmMain.Width > frmDebug.Left then
      frmMain.Left := frmDebug.Left - frmMain.Width;
  end;
end;

end.
