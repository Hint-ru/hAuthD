program hAuthD;

uses
  Forms,
  uMain in 'uMain.pas' {frmMain},
  uDebug in 'uDebug.pas' {frmDebug};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TfrmDebug, frmDebug);
  Application.Run;
end.
