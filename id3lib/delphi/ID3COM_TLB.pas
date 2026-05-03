unit ID3COM_TLB;

// ************************************************************************ //
// WARNING                                                                  //
// -------                                                                  //
// The types declared in this file were generated from data read from a     //
// Type Library. If this type library is explicitly or indirectly (via      //
// another type library referring to this type library) re-imported, or the //
// 'Refresh' command of the Type Library Editor activated while editing the //
// Type Library, the contents of this file will be regenerated and all      //
// manual modifications will be lost.                                       //
// ************************************************************************ //

// PASTLWTR : $Revision: 1.2 $
// File generated on 5/14/00 4:08:32 PM from Type Library described below.

// ************************************************************************ //
// Type Lib: C:\WINDOWS\DESKTOP\IDV3\ID3COM\RELEASE\ID3COM.DLL
// IID\LCID: {AEBA98B0-C36C-11D3-841B-0008C782A257}\0
// Helpfile: 
// HelpString: ID3COM 1.0 Type Library
// Version:    1.0
// ************************************************************************ //

interface

uses Windows, ActiveX, Classes, Graphics, OleCtrls, StdVCL;

// *********************************************************************//
// GUIDS declared in the TypeLibrary. Following prefixes are used:      //
//   Type Libraries     : LIBID_xxxx                                    //
//   CoClasses          : CLASS_xxxx                                    //
//   DISPInterfaces     : DIID_xxxx                                     //
//   Non-DISP interfaces: IID_xxxx                                      //
// *********************************************************************//
const
  LIBID_ID3COM: TGUID = '{AEBA98B0-C36C-11D3-841B-0008C782A257}';
  IID_IID3ComTag: TGUID = '{AEBA98BC-C36C-11D3-841B-0008C782A257}';
  CLASS_ID3ComTag: TGUID = '{AEBA98BD-C36C-11D3-841B-0008C782A257}';
  IID_IID3ComFrame: TGUID = '{AEBA98BE-C36C-11D3-841B-0008C782A257}';
  IID_IID3ComField: TGUID = '{A513A24E-C749-11D3-841C-0008C782A257}';
  CLASS_ID3ComFrame: TGUID = '{AEBA98BF-C36C-11D3-841B-0008C782A257}';
  CLASS_ID3ComField: TGUID = '{A513A24F-C749-11D3-841C-0008C782A257}';

// *********************************************************************//
// Declaration of Enumerations defined in Type Library                  //
// *********************************************************************//
// __MIDL___MIDL_itf_id3com_0000_0002 constants
type
  __MIDL___MIDL_itf_id3com_0000_0002 = TOleEnum;
const
  ID3_NOFRAME = $00000000;
  ID3_AUDIOCRYPTO = $00000001;
  ID3_PICTURE = $00000002;
  ID3_COMMENT = $00000003;
  ID3_COMMERCIAL = $00000004;
  ID3_CRYPTOREG = $00000005;
  ID3_EQUALIZATION = $00000006;
  ID3_EVENTTIMING = $00000007;
  ID3_GENERALOBJECT = $00000008;
  ID3_GROUPINGREG = $00000009;
  ID3_INVOLVEDPEOPLE = $0000000A;
  ID3_LINKEDINFO = $0000000B;
  ID3_CDID = $0000000C;
  ID3_MPEGLOOKUP = $0000000D;
  ID3_OWNERSHIP = $0000000E;
  ID3_PRIVATE = $0000000F;
  ID3_PLAYCOUNTER = $00000010;
  ID3_POPULARIMETER = $00000011;
  ID3_POSITIONSYNC = $00000012;
  ID3_BUFFERSIZE = $00000013;
  ID3_VOLUMEADJ = $00000014;
  ID3_REVERB = $00000015;
  ID3_SYNCEDLYRICS = $00000016;
  ID3_SYNCEDTEMPO = $00000017;
  ID3_ALBUM = $00000018;
  ID3_BPM = $00000019;
  ID3_COMPOSER = $0000001A;
  ID3_CONTENTTYPE = $0000001B;
  ID3_COPYRIGHT = $0000001C;
  ID3_DATE = $0000001D;
  ID3_PLAYLISTDELAY = $0000001E;
  ID3_ENCODEDBY = $0000001F;
  ID3_LYRICIST = $00000020;
  ID3_FILETYPE = $00000021;
  ID3_TIME = $00000022;
  ID3_CONTENTGROUP = $00000023;
  ID3_TITLE = $00000024;
  ID3_SUBTITLE = $00000025;
  ID3_INITIALKEY = $00000026;
  ID3_LANGUAGE = $00000027;
  ID3_SONGLEN = $00000028;
  ID3_MEDIATYPE = $00000029;
  ID3_ORIGALBUM = $0000002A;
  ID3_ORIGFILENAME = $0000002B;
  ID3_ORIGLYRICIST = $0000002C;
  ID3_ORIGARTIST = $0000002D;
  ID3_ORIGYEAR = $0000002E;
  ID3_FILEOWNER = $0000002F;
  ID3_LEADARTIST = $00000030;
  ID3_BAND = $00000031;
  ID3_CONDUCTOR = $00000032;
  ID3_MIXARTIST = $00000033;
  ID3_PARTINSET = $00000034;
  ID3_PUBLISHER = $00000035;
  ID3_TRACKNUM = $00000036;
  ID3_RECORDINGDATES = $00000037;
  ID3_NETRADIOSTATION = $00000038;
  ID3_NETRADIOOWNER = $00000039;
  ID3_SIZE = $0000003A;
  ID3_ISRC = $0000003B;
  ID3_ENCODERSETTINGS = $0000003C;
  ID3_USERTEXT = $0000003D;
  ID3_YEAR = $0000003E;
  ID3_UNIQUEFILEID = $0000003F;
  ID3_TERMSOFUSE = $00000040;
  ID3_UNSYNCEDLYRICS = $00000041;
  ID3_WWWCOMMERCIALINFO = $00000042;
  ID3_WWWCOPYRIGHT = $00000043;
  ID3_WWWAUDIOFILE = $00000044;
  ID3_WWWARTIST = $00000045;
  ID3_WWWAUDIOSOURCE = $00000046;
  ID3_WWWRADIOPAGE = $00000047;
  ID3_WWWPAYMENT = $00000048;
  ID3_WWWPUBLISHER = $00000049;
  ID3_WWWUSER = $0000004A;
  ID3_METACRYPTO = $0000004B;

// __MIDL___MIDL_itf_id3com_0000_0001 constants
type
  __MIDL___MIDL_itf_id3com_0000_0001 = TOleEnum;
const
  ID3_FIELD_NOFIELD = $00000000;
  ID3_FIELD_TEXTENC = $00000001;
  ID3_FIELD_TEXT = $00000002;
  ID3_FIELD_URL = $00000003;
  ID3_FIELD_DATA = $00000004;
  ID3_FIELD_DESCRIPTION = $00000005;
  ID3_FIELD_OWNER = $00000006;
  ID3_FIELD_EMAIL = $00000007;
  ID3_FIELD_RATING = $00000008;
  ID3_FIELD_FILENAME = $00000009;
  ID3_FIELD_LANGUAGE = $0000000A;
  ID3_FIELD_PICTURETYPE = $0000000B;
  ID3_FIELD_IMAGEFORMAT = $0000000C;
  ID3_FIELD_MIMETYPE = $0000000D;
  ID3_FIELD_COUNTER = $0000000E;
  ID3_FIELD_SYMBOL = $0000000F;
  ID3_FIELD_VOLUMEADJ = $00000010;
  ID3_FIELD_NUMBITS = $00000011;
  ID3_FIELD_VOLCHGRIGHT = $00000012;
  ID3_FIELD_VOLCHGLEFT = $00000013;
  ID3_FIELD_PEAKVOLRIGHT = $00000014;
  ID3_FIELD_PEAKVOLLEFT = $00000015;
  ID3_FIELD_LASTFIELDID = $00000016;

type

// *********************************************************************//
// Forward declaration of interfaces defined in Type Library            //
// *********************************************************************//
  IID3ComTag = interface;
  IID3ComTagDisp = dispinterface;
  IID3ComFrame = interface;
  IID3ComFrameDisp = dispinterface;
  IID3ComField = interface;
  IID3ComFieldDisp = dispinterface;

// *********************************************************************//
// Declaration of CoClasses defined in Type Library                     //
// (NOTE: Here we map each CoClass to its Default Interface)            //
// *********************************************************************//
  ID3ComTag = IID3ComTag;
  ID3ComFrame = IID3ComFrame;
  ID3ComField = IID3ComField;


// *********************************************************************//
// Declaration of structures, unions and aliases.                       //
// *********************************************************************//
  PWideString1 = ^WideString; {*}

  eID3FrameTypes = __MIDL___MIDL_itf_id3com_0000_0002; 
  eID3FieldTypes = __MIDL___MIDL_itf_id3com_0000_0001; 

// *********************************************************************//
// Interface: IID3ComTag
// Flags:     (4416) Dual OleAutomation Dispatchable
// GUID:      {AEBA98BC-C36C-11D3-841B-0008C782A257}
// *********************************************************************//
  IID3ComTag = interface(IDispatch)
    ['{AEBA98BC-C36C-11D3-841B-0008C782A257}']
    procedure Link(var FileName: WideString); safecall;
    procedure Clear; safecall;
    function Get_HasChanged: WordBool; safecall;
    function FindFrame(FrameID: eID3FrameTypes; CreateNewIfNotFound: WordBool): IID3ComFrame; safecall;
    function Get_NumFrames: Integer; safecall;
    function Get_FrameByNum(FrameNum: Integer): IID3ComFrame; safecall;
    procedure SaveV1Tag; safecall;
    procedure StripV1Tag; safecall;
    procedure SaveV2Tag; safecall;
    procedure StripV2Tag; safecall;
    function Get_Artist: WideString; safecall;
    procedure Set_Artist(const pVal: WideString); safecall;
    function Get_Album: WideString; safecall;
    procedure Set_Album(const pVal: WideString); safecall;
    function Get_Title: WideString; safecall;
    procedure Set_Title(const pVal: WideString); safecall;
    function Get_Comment: WideString; safecall;
    procedure Set_Comment(const pVal: WideString); safecall;
    function Get_Genre: Integer; safecall;
    procedure Set_Genre(pVal: Integer); safecall;
    function Get_Year: WideString; safecall;
    procedure Set_Year(const pVal: WideString); safecall;
    function Get_Track: Integer; safecall;
    procedure Set_Track(pVal: Integer); safecall;
    function Get_LastPlayed: TDateTime; safecall;
    procedure Set_LastPlayed(pVal: TDateTime); safecall;
    function Get_HasV1Tag: WordBool; safecall;
    function Get_HasV2Tag: WordBool; safecall;
    function Get_HasLyrics: WordBool; safecall;
    function FindFrameString(FrameID: eID3FrameTypes; FieldType: eID3FieldTypes; 
                             const FindString: WideString; CreateNewIfNotFound: WordBool): IID3ComFrame; safecall;
    function Get_PlayCount(const EMailAddress: WideString): Integer; safecall;
    procedure Set_PlayCount(const EMailAddress: WideString; pVal: Integer); safecall;
    function Get_Popularity(const EMailAddress: WideString): Smallint; safecall;
    procedure Set_Popularity(const EMailAddress: WideString; pVal: Smallint); safecall;
    function Get_TagCreated: TDateTime; safecall;
    procedure Set_TagCreated(pVal: TDateTime); safecall;
    function Get_PercentVolumeAdjust: Double; safecall;
    procedure Set_PercentVolumeAdjust(pVal: Double); safecall;
    procedure Set_Padding(Param1: WordBool); safecall;
    procedure Set_UnSync(Param1: WordBool); safecall;
    function Get__NewEnum: IUnknown; safecall;
    property HasChanged: WordBool read Get_HasChanged;
    property NumFrames: Integer read Get_NumFrames;
    property FrameByNum[FrameNum: Integer]: IID3ComFrame read Get_FrameByNum;
    property Artist: WideString read Get_Artist write Set_Artist;
    property Album: WideString read Get_Album write Set_Album;
    property Title: WideString read Get_Title write Set_Title;
    property Comment: WideString read Get_Comment write Set_Comment;
    property Genre: Integer read Get_Genre write Set_Genre;
    property Year: WideString read Get_Year write Set_Year;
    property Track: Integer read Get_Track write Set_Track;
    property LastPlayed: TDateTime read Get_LastPlayed write Set_LastPlayed;
    property HasV1Tag: WordBool read Get_HasV1Tag;
    property HasV2Tag: WordBool read Get_HasV2Tag;
    property HasLyrics: WordBool read Get_HasLyrics;
    property PlayCount[const EMailAddress: WideString]: Integer read Get_PlayCount write Set_PlayCount;
    property Popularity[const EMailAddress: WideString]: Smallint read Get_Popularity write Set_Popularity;
    property TagCreated: TDateTime read Get_TagCreated write Set_TagCreated;
    property PercentVolumeAdjust: Double read Get_PercentVolumeAdjust write Set_PercentVolumeAdjust;
    property Padding: WordBool write Set_Padding;
    property UnSync: WordBool write Set_UnSync;
    property _NewEnum: IUnknown read Get__NewEnum;
  end;

// *********************************************************************//
// DispIntf:  IID3ComTagDisp
// Flags:     (4416) Dual OleAutomation Dispatchable
// GUID:      {AEBA98BC-C36C-11D3-841B-0008C782A257}
// *********************************************************************//
  IID3ComTagDisp = dispinterface
    ['{AEBA98BC-C36C-11D3-841B-0008C782A257}']
    procedure Link(var FileName: WideString); dispid 1;
    procedure Clear; dispid 2;
    property HasChanged: WordBool readonly dispid 3;
    function FindFrame(FrameID: eID3FrameTypes; CreateNewIfNotFound: WordBool): IID3ComFrame; dispid 4;
    property NumFrames: Integer readonly dispid 5;
    property FrameByNum[FrameNum: Integer]: IID3ComFrame readonly dispid 6;
    procedure SaveV1Tag; dispid 7;
    procedure StripV1Tag; dispid 8;
    procedure SaveV2Tag; dispid 9;
    procedure StripV2Tag; dispid 10;
    property Artist: WideString dispid 11;
    property Album: WideString dispid 12;
    property Title: WideString dispid 13;
    property Comment: WideString dispid 14;
    property Genre: Integer dispid 15;
    property Year: WideString dispid 16;
    property Track: Integer dispid 17;
    property LastPlayed: TDateTime dispid 18;
    property HasV1Tag: WordBool readonly dispid 19;
    property HasV2Tag: WordBool readonly dispid 20;
    property HasLyrics: WordBool readonly dispid 21;
    function FindFrameString(FrameID: eID3FrameTypes; FieldType: eID3FieldTypes; 
                             const FindString: WideString; CreateNewIfNotFound: WordBool): IID3ComFrame; dispid 22;
    property PlayCount[const EMailAddress: WideString]: Integer dispid 23;
    property Popularity[const EMailAddress: WideString]: Smallint dispid 24;
    property TagCreated: TDateTime dispid 25;
    property PercentVolumeAdjust: Double dispid 26;
    property Padding: WordBool writeonly dispid 27;
    property UnSync: WordBool writeonly dispid 28;
    property _NewEnum: IUnknown readonly dispid -4;
  end;

// *********************************************************************//
// Interface: IID3ComFrame
// Flags:     (4416) Dual OleAutomation Dispatchable
// GUID:      {AEBA98BE-C36C-11D3-841B-0008C782A257}
// *********************************************************************//
  IID3ComFrame = interface(IDispatch)
    ['{AEBA98BE-C36C-11D3-841B-0008C782A257}']
    function Get_Field(FieldType: eID3FieldTypes): IID3ComField; safecall;
    procedure Clear; safecall;
    function Get_ID: eID3FrameTypes; safecall;
    procedure Set_ID(pVal: eID3FrameTypes); safecall;
    function Get_FrameName: WideString; safecall;
    function Get_Compressed: WordBool; safecall;
    procedure Set_Compressed(pVal: WordBool); safecall;
    property Field[FieldType: eID3FieldTypes]: IID3ComField read Get_Field;
    property ID: eID3FrameTypes read Get_ID write Set_ID;
    property FrameName: WideString read Get_FrameName;
    property Compressed: WordBool read Get_Compressed write Set_Compressed;
  end;

// *********************************************************************//
// DispIntf:  IID3ComFrameDisp
// Flags:     (4416) Dual OleAutomation Dispatchable
// GUID:      {AEBA98BE-C36C-11D3-841B-0008C782A257}
// *********************************************************************//
  IID3ComFrameDisp = dispinterface
    ['{AEBA98BE-C36C-11D3-841B-0008C782A257}']
    property Field[FieldType: eID3FieldTypes]: IID3ComField readonly dispid 1;
    procedure Clear; dispid 2;
    property ID: eID3FrameTypes dispid 3;
    property FrameName: WideString readonly dispid 4;
    property Compressed: WordBool dispid 5;
  end;

// *********************************************************************//
// Interface: IID3ComField
// Flags:     (4416) Dual OleAutomation Dispatchable
// GUID:      {A513A24E-C749-11D3-841C-0008C782A257}
// *********************************************************************//
  IID3ComField = interface(IDispatch)
    ['{A513A24E-C749-11D3-841C-0008C782A257}']
    function Get_Text(ItemNum: Integer): WideString; safecall;
    procedure Set_Text(ItemNum: Integer; const pVal: WideString); safecall;
    function Get_Long: Integer; safecall;
    procedure Set_Long(pVal: Integer); safecall;
    procedure Clear; safecall;
    procedure CopyDataToFile(const FileName: WideString); safecall;
    procedure CopyDataFromFile(const FileName: WideString); safecall;
    function Get_NumTextItems: Integer; safecall;
    property Text[ItemNum: Integer]: WideString read Get_Text write Set_Text;
    property Long: Integer read Get_Long write Set_Long;
    property NumTextItems: Integer read Get_NumTextItems;
  end;

// *********************************************************************//
// DispIntf:  IID3ComFieldDisp
// Flags:     (4416) Dual OleAutomation Dispatchable
// GUID:      {A513A24E-C749-11D3-841C-0008C782A257}
// *********************************************************************//
  IID3ComFieldDisp = dispinterface
    ['{A513A24E-C749-11D3-841C-0008C782A257}']
    property Text[ItemNum: Integer]: WideString dispid 1;
    property Long: Integer dispid 2;
    procedure Clear; dispid 3;
    procedure CopyDataToFile(const FileName: WideString); dispid 4;
    procedure CopyDataFromFile(const FileName: WideString); dispid 5;
    property NumTextItems: Integer readonly dispid 6;
  end;

  CoID3ComTag = class
    class function Create: IID3ComTag;
    class function CreateRemote(const MachineName: string): IID3ComTag;
  end;

  CoID3ComFrame = class
    class function Create: IID3ComFrame;
    class function CreateRemote(const MachineName: string): IID3ComFrame;
  end;

  CoID3ComField = class
    class function Create: IID3ComField;
    class function CreateRemote(const MachineName: string): IID3ComField;
  end;

implementation

uses ComObj;

class function CoID3ComTag.Create: IID3ComTag;
begin
  Result := CreateComObject(CLASS_ID3ComTag) as IID3ComTag;
end;

class function CoID3ComTag.CreateRemote(const MachineName: string): IID3ComTag;
begin
  Result := CreateRemoteComObject(MachineName, CLASS_ID3ComTag) as IID3ComTag;
end;

class function CoID3ComFrame.Create: IID3ComFrame;
begin
  Result := CreateComObject(CLASS_ID3ComFrame) as IID3ComFrame;
end;

class function CoID3ComFrame.CreateRemote(const MachineName: string): IID3ComFrame;
begin
  Result := CreateRemoteComObject(MachineName, CLASS_ID3ComFrame) as IID3ComFrame;
end;

class function CoID3ComField.Create: IID3ComField;
begin
  Result := CreateComObject(CLASS_ID3ComField) as IID3ComField;
end;

class function CoID3ComField.CreateRemote(const MachineName: string): IID3ComField;
begin
  Result := CreateRemoteComObject(MachineName, CLASS_ID3ComField) as IID3ComField;
end;

end.
