unit md5;

interface

uses Windows, SysUtils, Classes;

type
  PMD5Digest = ^TMD5Digest;

  TMD5Digest = record
    case Integer of
      0:
        (A, B, C, D: LongInt);
      1:
        (v: array [0 .. 15] of Byte);
  end;

function getmd5(s: string): string;

function MD5Str(const MD: TMD5Digest): string;

function MD5String(const s: string): TMD5Digest;

function MD5File(const FileName: string): TMD5Digest;

function MD5Stream(const Stream: TStream): TMD5Digest;

function MD5Buffer(const Buffer; Size: Integer): TMD5Digest;

function MD5DigestToStr(const Digest: TMD5Digest): string;

function MD5DigestCompare(const Digest1, Digest2: TMD5Digest): Boolean;

implementation

{
  Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
  rights reserved.

  License to copy and use this software is granted provided that it
  is identified as the "RSA Data Security, Inc. MD5 Message-Digest
  Algorithm" in all material mentioning or referencing this software
  or this function.

  License is also granted to make and use derivative works provided
  that such works are identified as "derived from the RSA Data
  Security, Inc. MD5 Message-Digest Algorithm" in all material
  mentioning or referencing the derived work.

  RSA Data Security, Inc. makes no representations concerning either
  the merchantability of this software or the suitability of this
  software for any particular purpose. It is provided "as is"
  without express or implied warranty of any kind.

  These notices must be retained in any copies of any part of this
  documentation and/or software.
}

type
  UINT4 = LongWord;

  PArray4UINT4 = ^TArray4UINT4;
  TArray4UINT4 = array [0 .. 3] of UINT4;
  PArray2UINT4 = ^TArray2UINT4;
  TArray2UINT4 = array [0 .. 1] of UINT4;
  PArray16Byte = ^TArray16Byte;
  TArray16Byte = array [0 .. 15] of Byte;
  PArray64Byte = ^TArray64Byte;
  TArray64Byte = array [0 .. 63] of Byte;

  PByteArray = ^TByteArray;
  TByteArray = array [0 .. 0] of Byte;

  PUINT4Array = ^TUINT4Array;
  TUINT4Array = array [0 .. 0] of UINT4;

  PMD5Context = ^TMD5Context;

  TMD5Context = record
    state: TArray4UINT4;
    count: TArray2UINT4;
    Buffer: TArray64Byte;
  end;

const
  S11 = 7;
  S12 = 12;
  S13 = 17;
  S14 = 22;
  S21 = 5;
  S22 = 9;
  S23 = 14;
  S24 = 20;
  S31 = 4;
  S32 = 11;
  S33 = 16;
  S34 = 23;
  S41 = 6;
  S42 = 10;
  S43 = 15;
  S44 = 21;

var
  Padding: TArray64Byte = ($80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

function _F(x, y, z: UINT4): UINT4;
begin
  Result := (((x) and (y)) or ((not x) and (z)));
end;

function _G(x, y, z: UINT4): UINT4;
begin
  Result := (((x) and (z)) or ((y) and (not z)));
end;

function _H(x, y, z: UINT4): UINT4;
begin
  Result := ((x) xor (y) xor (z));
end;

function _I(x, y, z: UINT4): UINT4;
begin
  Result := ((y) xor ((x) or (not z)));
end;

function ROTATE_LEFT(x, n: UINT4): UINT4;
begin
  Result := (((x) shl (n)) or ((x) shr (32 - (n))));
end;

procedure FF(var A: UINT4; B, C, D, x, s, ac: UINT4);
begin
  A := A + _F(B, C, D) + x + ac;
  A := ROTATE_LEFT(A, s);
  A := A + B;
end;

procedure GG(var A: UINT4; B, C, D, x, s, ac: UINT4);
begin
  A := A + _G(B, C, D) + x + ac;
  A := ROTATE_LEFT(A, s);
  A := A + B;
end;

procedure HH(var A: UINT4; B, C, D, x, s, ac: UINT4);
begin
  A := A + _H(B, C, D) + x + ac;
  A := ROTATE_LEFT(A, s);
  A := A + B;
end;

procedure II(var A: UINT4; B, C, D, x, s, ac: UINT4);
begin
  A := A + _I(B, C, D) + x + ac;
  A := ROTATE_LEFT(A, s);
  A := A + B;
end;

procedure MD5Encode(Output: PByteArray; Input: PUINT4Array; Len: LongWord);
var
  i, j: LongWord;
begin
  j := 0;
  i := 0;
  while j < Len do
  begin
    Output[j] := Byte(Input[i] and $FF);
    Output[j + 1] := Byte((Input[i] shr 8) and $FF);
    Output[j + 2] := Byte((Input[i] shr 16) and $FF);
    Output[j + 3] := Byte((Input[i] shr 24) and $FF);
    Inc(j, 4);
    Inc(i);
  end;
end;

procedure MD5Decode(Output: PUINT4Array; Input: PByteArray; Len: LongWord);
var
  i, j: LongWord;
begin
  j := 0;
  i := 0;
  while j < Len do
  begin
    Output[i] := UINT4(Input[j]) or (UINT4(Input[j + 1]) shl 8) or
      (UINT4(Input[j + 2]) shl 16) or (UINT4(Input[j + 3]) shl 24);
    Inc(j, 4);
    Inc(i);
  end;
end;

procedure MD5_memcpy(Output: PByteArray; Input: PByteArray; Len: LongWord);
begin
  Move(Input^, Output^, Len);
end;

procedure MD5_memset(Output: PByteArray; Value: Integer; Len: LongWord);
begin
  FillChar(Output^, Len, Byte(Value));
end;

function MD5Str(const MD: TMD5Digest): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to 15 do
    Result := Result + IntToHex(MD.v[i], 2);
end;

procedure MD5Transform(state: PArray4UINT4; Buffer: PArray64Byte);
var
  A, B, C, D: UINT4;
  x: array [0 .. 15] of UINT4;
begin
  A := state[0];
  B := state[1];
  C := state[2];
  D := state[3];
  MD5Decode(PUINT4Array(@x), PByteArray(Buffer), 64);

  FF(A, B, C, D, x[0], S11, $D76AA478);
  FF(D, A, B, C, x[1], S12, $E8C7B756);
  FF(C, D, A, B, x[2], S13, $242070DB);
  FF(B, C, D, A, x[3], S14, $C1BDCEEE);
  FF(A, B, C, D, x[4], S11, $F57C0FAF);
  FF(D, A, B, C, x[5], S12, $4787C62A);
  FF(C, D, A, B, x[6], S13, $A8304613);
  FF(B, C, D, A, x[7], S14, $FD469501);
  FF(A, B, C, D, x[8], S11, $698098D8);
  FF(D, A, B, C, x[9], S12, $8B44F7AF);
  FF(C, D, A, B, x[10], S13, $FFFF5BB1);
  FF(B, C, D, A, x[11], S14, $895CD7BE);
  FF(A, B, C, D, x[12], S11, $6B901122);
  FF(D, A, B, C, x[13], S12, $FD987193);
  FF(C, D, A, B, x[14], S13, $A679438E);
  FF(B, C, D, A, x[15], S14, $49B40821);

  GG(A, B, C, D, x[1], S21, $F61E2562);
  GG(D, A, B, C, x[6], S22, $C040B340);
  GG(C, D, A, B, x[11], S23, $265E5A51);
  GG(B, C, D, A, x[0], S24, $E9B6C7AA);
  GG(A, B, C, D, x[5], S21, $D62F105D);
  GG(D, A, B, C, x[10], S22, $2441453);
  GG(C, D, A, B, x[15], S23, $D8A1E681);
  GG(B, C, D, A, x[4], S24, $E7D3FBC8);
  GG(A, B, C, D, x[9], S21, $21E1CDE6);
  GG(D, A, B, C, x[14], S22, $C33707D6);
  GG(C, D, A, B, x[3], S23, $F4D50D87);

  GG(B, C, D, A, x[8], S24, $455A14ED);
  GG(A, B, C, D, x[13], S21, $A9E3E905);
  GG(D, A, B, C, x[2], S22, $FCEFA3F8);
  GG(C, D, A, B, x[7], S23, $676F02D9);
  GG(B, C, D, A, x[12], S24, $8D2A4C8A);

  HH(A, B, C, D, x[5], S31, $FFFA3942);
  HH(D, A, B, C, x[8], S32, $8771F681);
  HH(C, D, A, B, x[11], S33, $6D9D6122);
  HH(B, C, D, A, x[14], S34, $FDE5380C);
  HH(A, B, C, D, x[1], S31, $A4BEEA44);
  HH(D, A, B, C, x[4], S32, $4BDECFA9);
  HH(C, D, A, B, x[7], S33, $F6BB4B60);
  HH(B, C, D, A, x[10], S34, $BEBFBC70);
  HH(A, B, C, D, x[13], S31, $289B7EC6);
  HH(D, A, B, C, x[0], S32, $EAA127FA);
  HH(C, D, A, B, x[3], S33, $D4EF3085);
  HH(B, C, D, A, x[6], S34, $4881D05);
  HH(A, B, C, D, x[9], S31, $D9D4D039);
  HH(D, A, B, C, x[12], S32, $E6DB99E5);
  HH(C, D, A, B, x[15], S33, $1FA27CF8);
  HH(B, C, D, A, x[2], S34, $C4AC5665);

  II(A, B, C, D, x[0], S41, $F4292244);
  II(D, A, B, C, x[7], S42, $432AFF97);
  II(C, D, A, B, x[14], S43, $AB9423A7);
  II(B, C, D, A, x[5], S44, $FC93A039);
  II(A, B, C, D, x[12], S41, $655B59C3);
  II(D, A, B, C, x[3], S42, $8F0CCC92);
  II(C, D, A, B, x[10], S43, $FFEFF47D);
  II(B, C, D, A, x[1], S44, $85845DD1);
  II(A, B, C, D, x[8], S41, $6FA87E4F);
  II(D, A, B, C, x[15], S42, $FE2CE6E0);
  II(C, D, A, B, x[6], S43, $A3014314);
  II(B, C, D, A, x[13], S44, $4E0811A1);
  II(A, B, C, D, x[4], S41, $F7537E82);
  II(D, A, B, C, x[11], S42, $BD3AF235);
  II(C, D, A, B, x[2], S43, $2AD7D2BB);
  II(B, C, D, A, x[9], S44, $EB86D391);

  Inc(state[0], A);
  Inc(state[1], B);
  Inc(state[2], C);
  Inc(state[3], D);

  MD5_memset(PByteArray(@x), 0, SizeOf(x));
end;

procedure MD5Init(var Context: TMD5Context);
begin
  FillChar(Context, SizeOf(Context), 0);
  Context.state[0] := $67452301;
  Context.state[1] := $EFCDAB89;
  Context.state[2] := $98BADCFE;
  Context.state[3] := $10325476;
end;

procedure MD5Update(var Context: TMD5Context; Input: PByteArray;
  InputLen: LongWord);
var
  i, index, partLen: LongWord;

begin
  index := LongWord((Context.count[0] shr 3) and $3F);
  Inc(Context.count[0], UINT4(InputLen) shl 3);
  if Context.count[0] < UINT4(InputLen) shl 3 then
    Inc(Context.count[1]);
  Inc(Context.count[1], UINT4(InputLen) shr 29);
  partLen := 64 - index;
  if InputLen >= partLen then
  begin
    MD5_memcpy(PByteArray(@Context.Buffer[index]), Input, partLen);
    MD5Transform(@Context.state, @Context.Buffer);
    i := partLen;
    while i + 63 < InputLen do
    begin
      MD5Transform(@Context.state, PArray64Byte(@Input[i]));
      Inc(i, 64);
    end;
    index := 0;
  end
  else
    i := 0;
  MD5_memcpy(PByteArray(@Context.Buffer[index]), PByteArray(@Input[i]),
    InputLen - i);
end;

procedure MD5Final(var Digest: TMD5Digest; var Context: TMD5Context);
var
  bits: array [0 .. 7] of Byte;
  index, padLen: LongWord;
begin
  MD5Encode(PByteArray(@bits), PUINT4Array(@Context.count), 8);
  index := LongWord((Context.count[0] shr 3) and $3F);
  if index < 56 then
    padLen := 56 - index
  else
    padLen := 120 - index;
  MD5Update(Context, PByteArray(@Padding), padLen);
  MD5Update(Context, PByteArray(@bits), 8);
  MD5Encode(PByteArray(@Digest), PUINT4Array(@Context.state), 16);
  MD5_memset(PByteArray(@Context), 0, SizeOf(Context));
end;

function MD5DigestToStr(const Digest: TMD5Digest): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to 15 do
    Result := Result + IntToHex(Digest.v[i], 2);
end;

function MD5String(const s: string): TMD5Digest;
begin
  Result := MD5Buffer(PChar(s)^, Length(s));
end;

function MD5File(const FileName: string): TMD5Digest;
var
  F: TFileStream;
begin
  F := TFileStream.Create(FileName, fmOpenRead);
  try
    Result := MD5Stream(F);
  finally
    F.Free;
  end;
end;

function MD5Stream(const Stream: TStream): TMD5Digest;
var
  Context: TMD5Context;
  Buffer: array [0 .. 4095] of Byte;
  Size: Integer;
  ReadBytes: Integer;
  TotalBytes: Integer;
  SavePos: Integer;
begin
  MD5Init(Context);
  Size := Stream.Size;
  SavePos := Stream.Position;
  TotalBytes := 0;
  try
    Stream.Seek(0, soFromBeginning);
    repeat
      ReadBytes := Stream.Read(Buffer, SizeOf(Buffer));
      Inc(TotalBytes, ReadBytes);
      MD5Update(Context, @Buffer, ReadBytes);
    until (ReadBytes = 0) or (TotalBytes = Size);
  finally
    Stream.Seek(SavePos, soFromBeginning);
  end;
  MD5Final(Result, Context);
end;

function MD5Buffer(const Buffer; Size: Integer): TMD5Digest;
var
  Context: TMD5Context;
begin
  MD5Init(Context);
  MD5Update(Context, PByteArray(@Buffer), Size);
  MD5Final(Result, Context);
end;

function MD5DigestCompare(const Digest1, Digest2: TMD5Digest): Boolean;
begin
  Result := False;
  if Digest1.A <> Digest2.A then
    Exit;
  if Digest1.B <> Digest2.B then
    Exit;
  if Digest1.C <> Digest2.C then
    Exit;
  if Digest1.D <> Digest2.D then
    Exit;
  Result := True;
end;

function getmd5(s: string): string;
begin
  Result := ansilowercase(MD5Str(MD5String(s)));
end;

end.
