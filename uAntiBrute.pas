unit uAntiBrute;

interface

uses
  Windows, Messages, SysUtils, Classes;

type
  TAntiBruteItem = record
    tag: TDateTime;
    n: integer;
  end;

  PAntiBruteItem = ^TAntiBruteItem;

  TAntiBrute = class(TObject)
  private
    black, items: TStrings;
    FInterval, FPenalty, FMaxAttempts: integer;

    dt: record
      interval, penalty, trash: TDateTime;
    end;

    procedure SetInterval(value: integer);
    procedure SetPenalty(value: integer);
    procedure trash(init: boolean = false);
  public
    property interval: integer read FInterval write SetInterval;
    property penalty: integer read FPenalty write SetPenalty;
    property MaxAttempts: integer read FMaxAttempts write FMaxAttempts;

    function IsBrute(id: string): boolean;
    function IsNewBrute(id: string): boolean;
    procedure NotBrute(id: string);

    constructor Create;
    destructor Destroy; override;
  end;

implementation

procedure TAntiBrute.trash(init: boolean = false);

  procedure clear(l: TStrings; interval: TDateTime);
  var
    i: integer;
    o: PAntiBruteItem;
    n: TDateTime;
  begin
    n := now;
    for i := l.Count - 1 downto 0 do
    begin
      o := PAntiBruteItem(l.Objects[i]);
      if o^.tag + interval < n then
      begin
        dispose(o);
        l.Delete(i);
      end;
    end;
  end;

begin
  if (dt.trash < now) or init then
  begin
    dt.trash := now + EncodeTime(0, 1, 0, 0);
    if not init then
    begin
      clear(items, dt.interval);
      clear(black, dt.penalty);
    end;
  end;
end;

function TAntiBrute.IsBrute(id: string): boolean;
var
  n: integer;
  o: PAntiBruteItem;
begin
  result := false;
  n := black.IndexOf(id);
  if n <> -1 then
  begin
    o := PAntiBruteItem(black.Objects[n]);
    if o^.tag + dt.penalty < now then
    begin
      dispose(o);
      black.Delete(n);
    end
    else
    begin
      result := true;
    end;
  end;
end;

function TAntiBrute.IsNewBrute(id: string): boolean;
var
  n: integer;
  o: PAntiBruteItem;
begin
  result := false;
  trash;
  n := items.IndexOf(id);
  if n = -1 then
  begin
    new(o);
    o^.tag := now;
    o^.n := 0;
    n := items.AddObject(id, TObject(o));
  end
  else
  begin
    o := PAntiBruteItem(items.Objects[n]);
  end;
  if o^.tag + dt.interval < now then
  begin
    o^.tag := now;
    o^.n := 0;
  end;
  o^.n := o^.n + 1;
  if o^.n >= FMaxAttempts then
  begin
    result := true;
    items.Delete(n);
    n := black.IndexOf(id);
    if n = -1 then
    begin
      black.AddObject(id, TObject(o));
    end
    else
    begin
      dispose(o);
      o := PAntiBruteItem(black.Objects[n]);
    end;
    o^.tag := now;
  end;
end;

procedure TAntiBrute.NotBrute(id: string);
var
  n: integer;
  o: PAntiBruteItem;
begin
  n := items.IndexOf(id);
  if n <> -1 then
  begin
    o := PAntiBruteItem(items.Objects[n]);
    dispose(o);
    items.Delete(n);
  end;
end;

procedure TAntiBrute.SetInterval(value: integer);
begin
  if value <> FInterval then
  begin
    FInterval := value;
    dt.interval := value / SecsPerDay;
  end;
end;

procedure TAntiBrute.SetPenalty(value: integer);
begin
  if value <> FPenalty then
  begin
    FPenalty := value;
    dt.penalty := value / SecsPerDay;
  end;
end;

constructor TAntiBrute.Create;
begin
  black := TStringList.Create;
  items := TStringList.Create;
  interval := 60;
  penalty := 180;
  MaxAttempts := 5;
  trash(true);
end;

destructor TAntiBrute.Destroy;
begin
  black.Free;
  black := nil;
  items.Free;
  items := nil;
end;

end.
