function ReadC: Byte;
begin
  if Index < 1 then
    Index := 1;
  if Length(Pck) < Index then
    raise Exception.Create('Error in ReadC!');
  Result := Ord(Pck[Index]);
  Inc(Index);
end;

function ReadH: Word;
begin
  if Index < 1 then
    Index := 1;
  if Length(Pck) < Index + 1 then
    raise Exception.Create('Error in ReadH!');
  Move(Pck[Index], Result, 2);
  Inc(Index, 2);
end;

function ReadD: Integer;
begin
  if Index < 1 then
    Index := 1;
  if Length(Pck) < Index + 3 then
    raise Exception.Create('Error in ReadD!');
  Move(Pck[Index], Result, 4);
  Inc(Index, 4);
end;

function ReadQ: Int64;
begin
  if Index < 1 then
    Index := 1;
  if Length(Pck) < Index + 7 then
    raise Exception.Create('Error in ReadQ!');
  Move(Pck[Index], Result, 8);
  Inc(Index, 8);
end;

function ReadF: Double;
begin
  if Index < 1 then
    Index := 1;
  if Length(Pck) < Index + 7 then
    raise Exception.Create('Error in ReadF!');
  Move(Pck[Index], Result, 8);
  Inc(Index, 8);
end;

function ReadS: string;
var
  I, Len: Integer;
begin
  if Index < 1 then
    Index := 1;
  Result := '';
  I := Index;
  Len := Length(Pck);
  while True do
  begin
    if I + 1 > Len then
    begin
      Index := Len + 1;
      Result := 'Error in ReadS!';
      raise Exception.Create('Error in ReadS!');
      Exit;
    end;
    if Pck[I] = #0 then
    begin
      Result := UniToStr(Copy(Pck, Index, I - Index));
      Index := I + 2;
      Exit;
    end;
    Inc(I, 2);
  end;
end;

function EndOfPacket(RaiseException: Boolean = True): Boolean;
begin
  Result := Index = Length(Pck) + 1;
  if (not Result) and RaiseException then
    raise Exception.Create('EndOfPacket expected!');
end;
