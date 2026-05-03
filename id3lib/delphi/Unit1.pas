unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ID3COM_TLB, ComObj, FileCtrl;

type
  TForm1 = class(TForm)
    lb1: TListBox;
    DriveComboBox1: TDriveComboBox;
    DirectoryListBox1: TDirectoryListBox;
    FileListBox1: TFileListBox;
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    procedure FileListBox1Click(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
  private
    { Private declarations }
  public
    myTag : ID3ComTag;

    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.DFM}

procedure TForm1.FileListBox1Click(Sender: TObject);
var
    otag : CoID3ComTag;
    
    myFrame : ID3ComFrame;
    myField: ID3ComField;

    fname: WideString;
    x, n : integer;
    line: WideString;
begin
     lb1.Clear;
     myTag := otag.Create;
     fname := filelistbox1.FileName;
     myTag.Link (fname);

     for x := 0 to mytag.NumFrames -1 do
     begin
         myframe := mytag.FrameByNum[x];
         line := myFrame.FrameName;
         myfield := myFrame.Field[ID3_FIELD_DESCRIPTION];
         if (myfield <> nil) then
            line := line + ' ' + myfield.Text[1];

         myfield := myFrame.Field[ID3_FIELD_TEXT];
         if (myfield <> nil) then
           for n := 1 to myField.NumTextItems do
              line := line + ': ' + myfield.Text[n];
         lb1.items.add(line);
     end;
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
    if (myTag <> nil) Then
        if not myTag.HasV2Tag then
        begin
            myTag.SaveV2Tag;
            FileListBox1Click(nil);
        end
        else
            ShowMessage('File already Has V2 Tag');
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
    if (myTag <> nil) then
    begin
        myTag.StripV1Tag;
        FileListBox1Click(nil);
    end;
end;

procedure TForm1.Button3Click(Sender: TObject);
begin
    if (myTag <> nil) then
    begin
        myTag.StripV2Tag;
         FileListBox1Click(nil);
    end;
end;

procedure TForm1.Button4Click(Sender: TObject);
var
   myFrame: ID3ComFrame;
begin
    if (myTag <> nil) then
    begin
        myFrame := myTag.FindFrameString(ID3_USERTEXT, ID3_FIELD_DESCRIPTION, 'ID3ComTest', false);
        myFrame.Field[ID3_FIELD_TEXT].Text[1] := 'This is a test done at ' + DateTimeToStr(Now);
        myTag.SaveV2Tag;
        FileListBox1Click(nil);
    end;
end;

end.
