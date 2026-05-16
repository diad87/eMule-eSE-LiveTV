program id3com;

uses
  Forms,
  Unit1 in 'Unit1.pas' {Form1},
  ID3COM_TLB in 'ID3COM_TLB.pas';

{$R *.RES}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
