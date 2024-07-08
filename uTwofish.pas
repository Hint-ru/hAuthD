{
  ***************************************************
  * A binary compatible Twofish implementation      *
  * written by Dave Barton (davebarton@bigfoot.com) *
  * partially based on C source by                  *
  * Markus Hahn (hahn@flix.de)                      *
  ***************************************************
  * 128bit block encryption                         *
  * Variable size key - up to 256bit                *
  ***************************************************
}
unit uTwofish;

interface

uses
  Sysutils, Tools;

const
  BLU: array [0 .. 3] of DWord = (0, 8, 16, 24);
  TWOFISH_BLOCKSIZE = 16;
  INPUTWHITEN = 0;
  OUTPUTWHITEN = (TWOFISH_BLOCKSIZE div 4);
  NUMROUNDS = 16;
  ROUNDSUBKEYS = (OUTPUTWHITEN + TWOFISH_BLOCKSIZE div 4);
  TOTALSUBKEYS = (ROUNDSUBKEYS + NUMROUNDS * 2);
  RS_GF_FDBK = $14D;
  SK_STEP = $02020202;
  SK_BUMP = $01010101;
  SK_ROTL = 9;
  P_00 = 1;
  P_01 = 0;
  P_02 = 0;
  P_03 = (P_01 xor 1);
  P_04 = 1;
  P_10 = 0;
  P_11 = 0;
  P_12 = 1;
  P_13 = (P_11 xor 1);
  P_14 = 0;
  P_20 = 1;
  P_21 = 1;
  P_22 = 0;
  P_23 = (P_21 xor 1);
  P_24 = 0;
  P_30 = 0;
  P_31 = 1;
  P_32 = 1;
  P_33 = (P_31 xor 1);
  P_34 = 1;
  MDS_GF_FDBK = $169;

type
  TTwofishData = record
    KeyLen: DWord;
    SubKeys: array [0 .. TOTALSUBKEYS - 1] of DWord;
    sboxKeys: array [0 .. 3] of DWord;
    sbox: array [0 .. 3, 0 .. 255] of DWord;
    InitBlock: array [0 .. 15] of byte; { initial IV }
    LastBlock: array [0 .. 15] of byte; { current IV }
  end;

function TwofishSelfTest: boolean;
{ performs a self test on this implementation }
procedure TwofishInit(var xxData: TTwofishData; xxKey: pointer; xxLen: integer;
  xxIV: pointer);
{ initializes the TTwofishData structure with the key information and IV if applicable }
procedure TwofishBurn(var Data: TTwofishData);
{ erases all information about the key }

procedure TwofishEncryptECB(var Data: TTwofishData; InData, OutData: pointer);
{ encrypts the data in a 128bit block using the ECB mode }
procedure TwofishEncryptCBC(var Data: TTwofishData; InData, OutData: pointer);
{ encrypts the data in a 128bit block using the CBC chaining mode }
procedure TwofishEncryptOFB(var Data: TTwofishData; InData, OutData: pointer);
{ encrypts the data in a 128bit block using the OFB chaining mode }
procedure TwofishEncryptCFB(var Data: TTwofishData; InData, OutData: pointer;
  Len: integer);
{ encrypts Len bytes of data using the CFB chaining mode }
procedure TwofishEncryptOFBC(var Data: TTwofishData; InData, OutData: pointer;
  Len: integer);
{ encrypts Len bytes of data using the OFB counter chaining mode }

procedure TwofishDecryptECB(var Data: TTwofishData; InData, OutData: pointer);
{ decrypts the data in a 128bit block using the ECB mode }
procedure TwofishDecryptCBC(var Data: TTwofishData; InData, OutData: pointer);
{ decrypts the data in a 128bit block using the CBC chaining mode }
procedure TwofishDecryptOFB(var Data: TTwofishData; InData, OutData: pointer);
{ decrypts the data in a 128bit block using the OFB chaining mode }
procedure TwofishDecryptCFB(var Data: TTwofishData; InData, OutData: pointer;
  Len: integer);
{ decrypts Len bytes of data using the CFB chaining mode }
procedure TwofishDecryptOFBC(var Data: TTwofishData; InData, OutData: pointer;
  Len: integer);
{ decrypts Len bytes of data using the OFB counter chaining mode }

procedure TwofishReset(var Data: TTwofishData);
{ resets the chaining mode information }

{ ****************************************************************************** }
implementation

{$R-}
{$I Twofish.inc}

type
  PDWord = ^DWord;
  PDWordArray = ^TDWordArray;
  TDWordArray = array [0 .. 1023] of DWord;

var
  MDS: array [0 .. 3, 0 .. 255] of DWord;

function LFSR1(x: DWord): DWord;
begin
  if (x and 1) <> 0 then
    Result := (x shr 1) xor (MDS_GF_FDBK div 2)
  else
    Result := (x shr 1);
end;

function LFSR2(x: DWord): DWord;
begin
  if (x and 2) <> 0 then
    if (x and 1) <> 0 then
      Result := (x shr 2) xor (MDS_GF_FDBK div 2) xor (MDS_GF_FDBK div 4)
    else
      Result := (x shr 2) xor (MDS_GF_FDBK div 2)
  else if (x and 1) <> 0 then
    Result := (x shr 2) xor (MDS_GF_FDBK div 4)
  else
    Result := (x shr 2);
end;

function Mx_1(x: DWord): DWord;
begin
  Result := x;
end;

function Mx_X(x: DWord): DWord;
begin
  Result := x xor LFSR2(x);
end;

function Mx_Y(x: DWord): DWord;
begin
  Result := x xor LFSR1(x) xor LFSR2(x);
end;

const
Mul_1:

function(x: DWord): DWord = Mx_1;
Mul_X:
  function(x: DWord): DWord = Mx_X;
Mul_Y:
    function(x: DWord): DWord = Mx_Y;

      procedure PreCompMDS;
      var
        m1, mx, my: array [0 .. 1] of byte;
        nI: integer;
      begin
        for nI := 0 to 255 do
        begin
          m1[0] := p8x8[0, nI];
          mx[0] := Mul_X(m1[0]);
          my[0] := Mul_Y(m1[0]);
          m1[1] := p8x8[1, nI];
          mx[1] := Mul_X(m1[1]);
          my[1] := Mul_Y(m1[1]);
          MDS[0, nI] := (m1[P_00] shl 0) or (mx[P_00] shl 8) or
            (my[P_00] shl 16) or (my[P_00] shl 24);
          MDS[1, nI] := (my[P_10] shl 0) or (my[P_10] shl 8) or
            (mx[P_10] shl 16) or (m1[P_10] shl 24);
          MDS[2, nI] := (mx[P_20] shl 0) or (my[P_20] shl 8) or
            (m1[P_20] shl 16) or (my[P_20] shl 24);
          MDS[3, nI] := (mx[P_30] shl 0) or (m1[P_30] shl 8) or
            (my[P_30] shl 16) or (mx[P_30] shl 24);
        end;
      end;

      function RS_MDS_Encode(lK0, lK1: DWord): DWord;
      var
        lR, nI, nJ, lG2, lG3: DWord;
        bB: byte;
      begin
        lR := 0;
        for nI := 0 to 1 do
        begin
          if nI <> 0 then
            lR := lR xor lK0
          else
            lR := lR xor lK1;
          for nJ := 0 to 3 do
          begin
            bB := lR shr 24;
            if (bB and $80) <> 0 then
              lG2 := ((bB shl 1) xor RS_GF_FDBK) and $FF
            else
              lG2 := (bB shl 1) and $FF;
            if (bB and 1) <> 0 then
              lG3 := ((bB shr 1) and $7F) xor (RS_GF_FDBK shr 1) xor lG2
            else
              lG3 := ((bB shr 1) and $7F) xor lG2;
            lR := (lR shl 8) xor (lG3 shl 24) xor (lG2 shl 16)
              xor (lG3 shl 8) xor bB;
          end;
        end;
        Result := lR;
      end;

      function f32(x: DWord; K32: PDWordArray; Len: DWord): DWord;
      var
        t0, t1, t2, t3: DWord;
      begin
        t0 := x and $FF;
        t1 := (x shr 8) and $FF;
        t2 := (x shr 16) and $FF;
        t3 := x shr 24;
        if Len = 256 then
        begin
          t0 := p8x8[P_04, t0] xor ((K32[3]) and $FF);
          t1 := p8x8[P_14, t1] xor ((K32[3] shr 8) and $FF);
          t2 := p8x8[P_24, t2] xor ((K32[3] shr 16) and $FF);
          t3 := p8x8[P_34, t3] xor ((K32[3] shr 24));
        end;
        if Len >= 192 then
        begin
          t0 := p8x8[P_03, t0] xor ((K32[2]) and $FF);
          t1 := p8x8[P_13, t1] xor ((K32[2] shr 8) and $FF);
          t2 := p8x8[P_23, t2] xor ((K32[2] shr 16) and $FF);
          t3 := p8x8[P_33, t3] xor ((K32[2] shr 24));
        end;
        Result := MDS[0, p8x8[P_01, p8x8[P_02, t0] xor ((K32[1]) and $FF)
          ] xor ((K32[0]) and $FF)] xor MDS
          [1, p8x8[P_11, p8x8[P_12, t1] xor ((K32[1] shr 8) and $FF)
          ] xor ((K32[0] shr 8) and $FF)] xor MDS
          [2, p8x8[P_21, p8x8[P_22, t2] xor ((K32[1] shr 16) and $FF)
          ] xor ((K32[0] shr 16) and $FF)] xor MDS
          [3, p8x8[P_31, p8x8[P_32, t3] xor ((K32[1] shr 24))
          ] xor ((K32[0] shr 24))];
      end;

      function TwofishSelfTest;
      const
        Key: array [0 .. 31] of byte = ($01, $23, $45, $67, $89, $AB, $CD, $EF,
          $FE, $DC, $BA, $98, $76, $54, $32, $10, $00, $11, $22, $33, $44, $55,
          $66, $77, $88, $99, $AA, $BB, $CC, $DD, $EE, $FF);
        InBlock: array [0 .. 15] of byte = ($0, $0, $0, $0, $0, $0, $0, $0, $0,
          $0, $0, $0, $0, $0, $0, $0);
        OutBlock: array [0 .. 15] of byte = ($37, $52, $7B, $E0, $05, $23, $34,
          $B8, $9F, $0C, $FC, $CA, $E8, $7C, $FA, $20);
      var
        Block: array [0 .. 15] of byte;
        Data: TTwofishData;
      begin
        TwofishInit(Data, @Key, Sizeof(Key), nil);
        TwofishEncryptECB(Data, @InBlock, @Block);
        Result := CompareMem(@Block, @OutBlock, Sizeof(Block));
        TwofishDecryptECB(Data, @Block, @Block);
        Result := Result and CompareMem(@Block, @InBlock, Sizeof(Block));
        TwofishBurn(Data);
      end;

      procedure TwofishInit;
        procedure Xor256(Dst, Src: PDWordArray; v: byte);
        var
          i: DWord;
        begin
          for i := 0 to 63 do
            Dst[i] := Src[i] xor (v * $01010101);
        end;

      var
        key32: array [0 .. 7] of DWord;
        k32e, k32o: array [0 .. 3] of DWord;
        k64Cnt, xxi, xxj, xxA, xxB, xxq, subkeyCnt: DWord;
        L0, L1: array [0 .. 255] of byte;
      begin
        if (xxLen <= 0) or (xxLen > 32) then
          raise Exception.Create
            ('Key (password) has to be between 1 and 32 bytes.' + #13 +
            'If you want to use a longer password please check' + #13 +
            '"Use Hash of password" in the password dialog.');
        with xxData do
        begin
          if xxIV = nil then
          begin
            FillChar(InitBlock, 16, 0);
            FillChar(LastBlock, 16, 0);
          end
          else
          begin
            Move(xxIV^, InitBlock, 16);
            Move(xxIV^, LastBlock, 16);
          end;
          FillChar(key32, Sizeof(key32), 0);
          Move(xxKey^, key32, xxLen);
          if xxLen <= 16 then // pad the key to either 128bit, 192bit or 256bit
            xxLen := 128
          else if xxLen <= 24 then
            xxLen := 192
          else
            xxLen := 256;
          subkeyCnt := ROUNDSUBKEYS + 2 * NUMROUNDS;
          KeyLen := xxLen;
          k64Cnt := xxLen div 64;
          xxj := k64Cnt - 1;
          for xxi := 0 to xxj do
          begin
            k32e[xxi] := key32[2 * xxi];
            k32o[xxi] := key32[2 * xxi + 1];
            sboxKeys[xxj] := RS_MDS_Encode(k32e[xxi], k32o[xxi]);
            Dec(xxj);
          end;
          xxq := 0;
          for xxi := 0 to ((subkeyCnt div 2) - 1) do
          begin
            xxA := f32(xxq, @k32e, xxLen);
            xxB := f32(xxq + SK_BUMP, @k32o, xxLen);
            xxB := LRot32(xxB, 8);
            SubKeys[2 * xxi] := xxA + xxB;
            xxB := xxA + 2 * xxB;
            SubKeys[2 * xxi + 1] := LRot32(xxB, SK_ROTL);
            Inc(xxq, SK_STEP);
          end;
          case xxLen of
            128:
              begin
                Xor256(@L0, @p8x8[P_02], (sboxKeys[1] and $FF));
                xxA := (sboxKeys[0] and $FF);
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[0 and 2, 2 * xxi + (0 and 1)] :=
                    MDS[0, p8x8[P_01, L0[xxi]] xor xxA];
                  sbox[0 and 2, 2 * xxi + (0 and 1) + 2] :=
                    MDS[0, p8x8[P_01, L0[xxi + 1]] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @p8x8[P_12], (sboxKeys[1] shr 8) and $FF);
                xxA := (sboxKeys[0] shr 8) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[1 and 2, 2 * xxi + (1 and 1)] :=
                    MDS[1, p8x8[P_11, L0[xxi]] xor xxA];
                  sbox[1 and 2, 2 * xxi + (1 and 1) + 2] :=
                    MDS[1, p8x8[P_11, L0[xxi + 1]] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @p8x8[P_22], (sboxKeys[1] shr 16) and $FF);
                xxA := (sboxKeys[0] shr 16) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[2 and 2, 2 * xxi + (2 and 1)] :=
                    MDS[2, p8x8[P_21, L0[xxi]] xor xxA];
                  sbox[2 and 2, 2 * xxi + (2 and 1) + 2] :=
                    MDS[2, p8x8[P_21, L0[xxi + 1]] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @p8x8[P_32], (sboxKeys[1] shr 24));
                xxA := (sboxKeys[0] shr 24);
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[3 and 2, 2 * xxi + (3 and 1)] :=
                    MDS[3, p8x8[P_31, L0[xxi]] xor xxA];
                  sbox[3 and 2, 2 * xxi + (3 and 1) + 2] :=
                    MDS[3, p8x8[P_31, L0[xxi + 1]] xor xxA];
                  Inc(xxi, 2);
                end;
              end;
            192:
              begin
                Xor256(@L0, @p8x8[P_03], sboxKeys[2] and $FF);
                xxA := sboxKeys[0] and $FF;
                xxB := sboxKeys[1] and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[0 and 2, 2 * xxi + (0 and 1)] :=
                    MDS[0, p8x8[P_01, p8x8[P_02, L0[xxi]] xor xxB] xor xxA];
                  sbox[0 and 2, 2 * xxi + (0 and 1) + 2] :=
                    MDS[0, p8x8[P_01, p8x8[P_02, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @p8x8[P_13], (sboxKeys[2] shr 8) and $FF);
                xxA := (sboxKeys[0] shr 8) and $FF;
                xxB := (sboxKeys[1] shr 8) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[1 and 2, 2 * xxi + (1 and 1)] :=
                    MDS[1, p8x8[P_11, p8x8[P_12, L0[xxi]] xor xxB] xor xxA];
                  sbox[1 and 2, 2 * xxi + (1 and 1) + 2] :=
                    MDS[1, p8x8[P_11, p8x8[P_12, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @p8x8[P_23], (sboxKeys[2] shr 16) and $FF);
                xxA := (sboxKeys[0] shr 16) and $FF;
                xxB := (sboxKeys[1] shr 16) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[2 and 2, 2 * xxi + (2 and 1)] :=
                    MDS[2, p8x8[P_21, p8x8[P_22, L0[xxi]] xor xxB] xor xxA];
                  sbox[2 and 2, 2 * xxi + (2 and 1) + 2] :=
                    MDS[2, p8x8[P_21, p8x8[P_22, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @p8x8[P_33], (sboxKeys[2] shr 24));
                xxA := (sboxKeys[0] shr 24);
                xxB := (sboxKeys[1] shr 24);
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[3 and 2, 2 * xxi + (3 and 1)] :=
                    MDS[3, p8x8[P_31, p8x8[P_32, L0[xxi]] xor xxB] xor xxA];
                  sbox[3 and 2, 2 * xxi + (3 and 1) + 2] :=
                    MDS[3, p8x8[P_31, p8x8[P_32, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
              end;
            256:
              begin
                Xor256(@L1, @p8x8[P_04], (sboxKeys[3]) and $FF);
                xxi := 0;
                while xxi < 256 do
                begin
                  L0[xxi] := p8x8[P_03, L1[xxi]];
                  L0[xxi + 1] := p8x8[P_03, L1[xxi + 1]];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @L0, (sboxKeys[2]) and $FF);
                xxA := (sboxKeys[0]) and $FF;
                xxB := (sboxKeys[1]) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[0 and 2, 2 * xxi + (0 and 1)] :=
                    MDS[0, p8x8[P_01, p8x8[P_02, L0[xxi]] xor xxB] xor xxA];
                  sbox[0 and 2, 2 * xxi + (0 and 1) + 2] :=
                    MDS[0, p8x8[P_01, p8x8[P_02, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L1, @p8x8[P_14], (sboxKeys[3] shr 8) and $FF);
                xxi := 0;
                while xxi < 256 do
                begin
                  L0[xxi] := p8x8[P_13, L1[xxi]];
                  L0[xxi + 1] := p8x8[P_13, L1[xxi + 1]];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @L0, (sboxKeys[2] shr 8) and $FF);
                xxA := (sboxKeys[0] shr 8) and $FF;
                xxB := (sboxKeys[1] shr 8) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[1 and 2, 2 * xxi + (1 and 1)] :=
                    MDS[1, p8x8[P_11, p8x8[P_12, L0[xxi]] xor xxB] xor xxA];
                  sbox[1 and 2, 2 * xxi + (1 and 1) + 2] :=
                    MDS[1, p8x8[P_11, p8x8[P_12, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;

                Xor256(@L1, @p8x8[P_24], (sboxKeys[3] shr 16) and $FF);
                xxi := 0;
                while xxi < 256 do
                begin
                  L0[xxi] := p8x8[P_23, L1[xxi]];
                  L0[xxi + 1] := p8x8[P_23, L1[xxi + 1]];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @L0, (sboxKeys[2] shr 16) and $FF);
                xxA := (sboxKeys[0] shr 16) and $FF;
                xxB := (sboxKeys[1] shr 16) and $FF;
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[2 and 2, 2 * xxi + (2 and 1)] :=
                    MDS[2, p8x8[P_21, p8x8[P_22, L0[xxi]] xor xxB] xor xxA];
                  sbox[2 and 2, 2 * xxi + (2 and 1) + 2] :=
                    MDS[2, p8x8[P_21, p8x8[P_22, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
                Xor256(@L1, @p8x8[P_34], (sboxKeys[3] shr 24));
                xxi := 0;
                while xxi < 256 do
                begin
                  L0[xxi] := p8x8[P_33, L1[xxi]];
                  L0[xxi + 1] := p8x8[P_33, L1[xxi + 1]];
                  Inc(xxi, 2);
                end;
                Xor256(@L0, @L0, (sboxKeys[2] shr 24));
                xxA := (sboxKeys[0] shr 24);
                xxB := (sboxKeys[1] shr 24);
                xxi := 0;
                while xxi < 256 do
                begin
                  sbox[3 and 2, 2 * xxi + (3 and 1)] :=
                    MDS[3, p8x8[P_31, p8x8[P_32, L0[xxi]] xor xxB] xor xxA];
                  sbox[3 and 2, 2 * xxi + (3 and 1) + 2] :=
                    MDS[3, p8x8[P_31, p8x8[P_32, L0[xxi + 1]] xor xxB] xor xxA];
                  Inc(xxi, 2);
                end;
              end;
          end;
        end;
      end;

      procedure TwofishBurn;
      begin
        FillChar(Data, Sizeof(Data), 0);
      end;

      procedure TwofishEncryptECB;
      var
        i: integer;
        t0, t1: DWord;
        x: array [0 .. 3] of DWord;
      begin
        x[0] := PDWord(InData)^ xor Data.SubKeys[INPUTWHITEN];
        x[1] := PDWord(integer(InData) + 4)^ xor Data.SubKeys[INPUTWHITEN + 1];
        x[2] := PDWord(integer(InData) + 8)^ xor Data.SubKeys[INPUTWHITEN + 2];
        x[3] := PDWord(integer(InData) + 12)^ xor Data.SubKeys[INPUTWHITEN + 3];
        with Data do
        begin
          i := 0;
          while i <= NUMROUNDS - 2 do
          begin
            t0 := Data.sbox[0, 2 * (((x[0]) shr (BLU[(0) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[0]) shr (BLU[(1) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[0]) shr (BLU[(2) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[0]) shr (BLU[(3) and 3])) and
              $FF) + 1];
            t1 := Data.sbox[0, 2 * (((x[1]) shr (BLU[(3) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[1]) shr (BLU[(4) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[1]) shr (BLU[(5) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[1]) shr (BLU[(6) and 3])) and
              $FF) + 1];
            x[3] := LRot32(x[3], 1);
            x[2] := x[2] xor (t0 + t1 + Data.SubKeys[ROUNDSUBKEYS + 2 * i]);
            x[3] := x[3] xor (t0 + 2 * t1 + Data.SubKeys[ROUNDSUBKEYS + 2
              * i + 1]);
            x[2] := RRot32(x[2], 1);

            t0 := Data.sbox[0, 2 * (((x[2]) shr (BLU[(0) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[2]) shr (BLU[(1) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[2]) shr (BLU[(2) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[2]) shr (BLU[(3) and 3])) and
              $FF) + 1];
            t1 := Data.sbox[0, 2 * (((x[3]) shr (BLU[(3) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[3]) shr (BLU[(4) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[3]) shr (BLU[(5) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[3]) shr (BLU[(6) and 3])) and
              $FF) + 1];
            x[1] := LRot32(x[1], 1);
            x[0] := x[0] xor (t0 + t1 + Data.SubKeys[ROUNDSUBKEYS + 2 *
              (i + 1)]);
            x[1] := x[1] xor (t0 + 2 * t1 + Data.SubKeys[ROUNDSUBKEYS + 2 *
              (i + 1) + 1]);
            x[0] := RRot32(x[0], 1);
            Inc(i, 2);
          end;
        end;
        PDWord(integer(OutData) + 0)^ := x[2] xor Data.SubKeys[OUTPUTWHITEN];
        PDWord(integer(OutData) + 4)^ := x[3] xor Data.SubKeys
          [OUTPUTWHITEN + 1];
        PDWord(integer(OutData) + 8)^ := x[0] xor Data.SubKeys
          [OUTPUTWHITEN + 2];
        PDWord(integer(OutData) + 12)^ := x[1] xor Data.SubKeys
          [OUTPUTWHITEN + 3];
      end;

      procedure TwofishDecryptECB;
      var
        i: integer;
        t0, t1: DWord;
        x: array [0 .. 3] of DWord;
      begin
        x[2] := PDWord(InData)^ xor Data.SubKeys[OUTPUTWHITEN];
        x[3] := PDWord(integer(InData) + 4)^ xor Data.SubKeys[OUTPUTWHITEN + 1];
        x[0] := PDWord(integer(InData) + 8)^ xor Data.SubKeys[OUTPUTWHITEN + 2];
        x[1] := PDWord(integer(InData) + 12)^ xor Data.SubKeys
          [OUTPUTWHITEN + 3];
        with Data do
        begin
          i := NUMROUNDS - 2;
          while i >= 0 do
          begin
            t0 := Data.sbox[0, 2 * (((x[2]) shr (BLU[(0) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[2]) shr (BLU[(1) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[2]) shr (BLU[(2) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[2]) shr (BLU[(3) and 3])) and
              $FF) + 1];
            t1 := Data.sbox[0, 2 * (((x[3]) shr (BLU[(3) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[3]) shr (BLU[(4) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[3]) shr (BLU[(5) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[3]) shr (BLU[(6) and 3])) and
              $FF) + 1];
            x[0] := LRot32(x[0], 1);
            x[0] := x[0] xor (t0 + t1 + Data.SubKeys[ROUNDSUBKEYS + 2 *
              (i + 1)]);
            x[1] := x[1] xor (t0 + 2 * t1 + Data.SubKeys[ROUNDSUBKEYS + 2 *
              (i + 1) + 1]);
            x[1] := RRot32(x[1], 1);

            t0 := Data.sbox[0, 2 * (((x[0]) shr (BLU[(0) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[0]) shr (BLU[(1) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[0]) shr (BLU[(2) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[0]) shr (BLU[(3) and 3])) and
              $FF) + 1];
            t1 := Data.sbox[0, 2 * (((x[1]) shr (BLU[(3) and 3])) and $FF)
              ] xor Data.sbox[0, 2 * (((x[1]) shr (BLU[(4) and 3])) and $FF) +
              1] xor Data.sbox[2, 2 * (((x[1]) shr (BLU[(5) and 3])) and $FF)
              ] xor Data.sbox[2, 2 * (((x[1]) shr (BLU[(6) and 3])) and
              $FF) + 1];
            x[2] := LRot32(x[2], 1);
            x[2] := x[2] xor (t0 + t1 + Data.SubKeys[ROUNDSUBKEYS + 2 * i]);
            x[3] := x[3] xor (t0 + 2 * t1 + Data.SubKeys[ROUNDSUBKEYS + 2
              * i + 1]);
            x[3] := RRot32(x[3], 1);
            Dec(i, 2);
          end;
        end;
        PDWord(integer(OutData) + 0)^ := x[0] xor Data.SubKeys[INPUTWHITEN];
        PDWord(integer(OutData) + 4)^ := x[1] xor Data.SubKeys[INPUTWHITEN + 1];
        PDWord(integer(OutData) + 8)^ := x[2] xor Data.SubKeys[INPUTWHITEN + 2];
        PDWord(integer(OutData) + 12)^ := x[3] xor Data.SubKeys
          [INPUTWHITEN + 3];
      end;

      procedure TwofishEncryptCBC;
      begin
        XorBlock(InData, @Data.LastBlock, OutData, 16);
        TwofishEncryptECB(Data, OutData, OutData);
        Move(OutData^, Data.LastBlock, 16);
      end;

      procedure TwofishDecryptCBC;
      var
        TempBlock: array [0 .. 15] of byte;
      begin
        Move(InData^, TempBlock, 16);
        TwofishDecryptECB(Data, InData, OutData);
        XorBlock(OutData, @Data.LastBlock, OutData, 16);
        Move(TempBlock, Data.LastBlock, 16);
      end;

      procedure TwofishEncryptCFB;
      var
        i: integer;
        TempBlock: array [0 .. 15] of byte;
      begin
        for i := 0 to Len - 1 do
        begin
          TwofishEncryptECB(Data, @Data.LastBlock, @TempBlock);
          PByteArray(OutData)[i] := PByteArray(InData)[i] xor TempBlock[0];
          Move(Data.LastBlock[1], Data.LastBlock[0], 15);
          Data.LastBlock[15] := PByteArray(OutData)[i];
        end;
      end;

      procedure TwofishDecryptCFB;
      var
        i: integer;
        TempBlock: array [0 .. 15] of byte;
        b: byte;
      begin
        for i := 0 to Len - 1 do
        begin
          b := PByteArray(InData)[i];
          TwofishEncryptECB(Data, @Data.LastBlock, @TempBlock);
          PByteArray(OutData)[i] := PByteArray(InData)[i] xor TempBlock[0];
          Move(Data.LastBlock[1], Data.LastBlock[0], 15);
          Data.LastBlock[15] := b;
        end;
      end;

      procedure TwofishEncryptOFB;
      begin
        TwofishEncryptECB(Data, @Data.LastBlock, @Data.LastBlock);
        XorBlock(@Data.LastBlock, InData, OutData, 16);
      end;

      procedure TwofishDecryptOFB;
      begin
        TwofishEncryptECB(Data, @Data.LastBlock, @Data.LastBlock);
        XorBlock(@Data.LastBlock, InData, OutData, 16);
      end;

      procedure TwofishEncryptOFBC;
      var
        i: integer;
        TempBlock: array [0 .. 15] of byte;
      begin
        for i := 0 to Len - 1 do
        begin
          TwofishEncryptECB(Data, @Data.LastBlock, @TempBlock);
          PByteArray(OutData)[i] := PByteArray(InData)[i] xor TempBlock[0];
          IncBlock(@Data.LastBlock, 16);
        end;
      end;

      procedure TwofishDecryptOFBC;
      var
        i: integer;
        TempBlock: array [0 .. 15] of byte;
      begin
        for i := 0 to Len - 1 do
        begin
          TwofishEncryptECB(Data, @Data.LastBlock, @TempBlock);
          PByteArray(OutData)[i] := PByteArray(InData)[i] xor TempBlock[0];
          IncBlock(@Data.LastBlock, 16);
        end;
      end;

      procedure TwofishReset;
      begin
        Move(Data.InitBlock, Data.LastBlock, 16);
      end;

initialization

PreCompMDS;

end.
