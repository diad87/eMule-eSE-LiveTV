unit id3lib;

// Delphi 5, 6, 7 interface unit to ID3lib
// by Jiri Hajek (jh@songs-db.com)
// Created: 1.2.2001
// Updated: 12.10.2002
//   - calling conventions changed: cdecl to stdcall
//   - new frame ids

interface

{$MINENUMSIZE 4}     // IMPORTANT - because we need to send enumerated types as 4-byte integers !!!!

const
  ID3_TAGHEADERSIZE  =  10;

  // error constants
  ID3E_NoError = 0;                 //**< No error reported */
  ID3E_NoMemory = 1;                //**< No available memory */
  ID3E_NoData = 2;                  //**< No data to parse */
  ID3E_BadData = 3;                 //**< Improperly formatted data */
  ID3E_NoBuffer = 4;                //**< No buffer to write to */
  ID3E_SmallBuffer = 5;             //**< Buffer is too small */
  ID3E_InvalidFrameID = 6;          //**< Invalid frame id */
  ID3E_FieldNotFound = 7;           //**< Requested field not found */
  ID3E_UnknownFieldType = 8;        //**< Unknown field type */
  ID3E_TagAlreadyAttached = 9;      //**< Tag is already attached to a file */
  ID3E_InvalidTagVersion =10;       //**< Invalid tag version */
  ID3E_NoFile =11;                  //**< No file to parse */
  ID3E_ReadOnly =12;                //**< Attempting to write to a read-only file */
  ID3E_zlibError =13;               //**< Error in compression/uncompression */

type
{** The various types of tags that id3lib can handle
 **}
 ID3_TagType = integer;
const
  ID3TT_NONE       =      0;    //**< Represents an empty or non-existant tag */
  ID3TT_ID3V1      = 1 shl 0;   //**< Represents an id3v1 or id3v1.1 tag */
  ID3TT_ID3V2      = 1 shl 1;   //**< Represents an id3v2 tag */
  ID3TT_LYRICS3    = 1 shl 2;   //**< Represents a Lyrics3 tag */
  ID3TT_LYRICS3V2  = 1 shl 3;   //**< Represents a Lyrics3 v2.00 tag */
  ID3TT_MUSICMATCH = 1 shl 4;   //**< Represents a MusicMatch tag */
   //**< Represents a Lyrics3 tag (for backwards compatibility) */
  ID3TT_LYRICS     = ID3TT_LYRICS3;
  //** Represents both id3 tags: id3v1 and id3v2 */
  ID3TT_ID3        = ID3TT_ID3V1 or ID3TT_ID3V2;
  //** Represents all possible types of tags */
  ID3TT_ALL        = not ID3TT_NONE;
  //** Represents all tag types that can be prepended to a file */
  ID3TT_PREPENDED  = ID3TT_ID3V2;
  //** Represents all tag types that can be appended to a file */
  ID3TT_APPENDED   = ID3TT_ALL and not ID3TT_ID3V2;

type
{** \enum ID3_TextEnc
 ** Enumeration of the types of text encodings: ascii or unicode
 **}
ID3_TextEnc =
(
  ID3TE_NONE = -1,
  ID3TE_ISO8859_1,
  ID3TE_UTF16,
  ID3TE_UTF16BE,
  ID3TE_UTF8,
  ID3TE_NUMENCODINGS,
  ID3TE_ASCII = ID3TE_ISO8859_1,
  ID3TE_UNICODE = ID3TE_UTF16
);

type
 {**
 ** Enumeration of the different types of fields in a frame.
 **}
ID3_FieldID =
(
  ID3FN_NOFIELD,    //**< No field */
  ID3FN_TEXTENC,        //**< Text encoding (unicode or ASCII) */
  ID3FN_TEXT,           //**< Text field */
  ID3FN_URL,            //**< A URL */
  ID3FN_DATA,           //**< Data field */
  ID3FN_DESCRIPTION,    //**< Description field */
  ID3FN_OWNER,          //**< Owner field */
  ID3FN_EMAIL,          //**< Email field */
  ID3FN_RATING,         //**< Rating field */
  ID3FN_FILENAME,       //**< Filename field */
  ID3FN_LANGUAGE,       //**< Language field */
  ID3FN_PICTURETYPE,    //**< Picture type field */
  ID3FN_IMAGEFORMAT,    //**< Image format field */
  ID3FN_MIMETYPE,       //**< Mimetype field */
  ID3FN_COUNTER,        //**< Counter field */
  ID3FN_ID,             //**< Identifier/Symbol field */
  ID3FN_VOLUMEADJ,      //**< Volume adjustment field */
  ID3FN_NUMBITS,        //**< Number of bits field */
  ID3FN_VOLCHGRIGHT,    //**< Volume chage on the right channel */
  ID3FN_VOLCHGLEFT,     //**< Volume chage on the left channel */
  ID3FN_PEAKVOLRIGHT,   //**< Peak volume on the right channel */
  ID3FN_PEAKVOLLEFT,    //**< Peak volume on the left channel */
  ID3FN_TIMESTAMPFORMAT,//**< SYLT Timestamp Format */
  ID3FN_CONTENTTYPE,    //**< SYLT content type */
  ID3FN_LASTFIELDID     //**< Last field placeholder */
);

{**
 ** Enumeration of the different types of frames recognized by id3lib
 **}
  ID3_FrameID = 
(
  { ???? } ID3FID_NOFRAME = 0,       //< No known frame */
  { AENC } ID3FID_AUDIOCRYPTO,       //< Audio encryption */
  { APIC } ID3FID_PICTURE,           //< Attached picture */
  { ASPI } ID3FID_AUDIOSEEKPOINT,    //< Audio seek point index */
  { COMM } ID3FID_COMMENT,           //< Comments */
  { COMR } ID3FID_COMMERCIAL,        //< Commercial frame */
  { ENCR } ID3FID_CRYPTOREG,         //< Encryption method registration */
  { EQU2 } ID3FID_EQUALIZATION2,     //< Equalisation (2) */
  { EQUA } ID3FID_EQUALIZATION,      //< Equalization */
  { ETCO } ID3FID_EVENTTIMING,       //< Event timing codes */
  { GEOB } ID3FID_GENERALOBJECT,     //< General encapsulated object */
  { GRID } ID3FID_GROUPINGREG,       //< Group identification registration */
  { IPLS } ID3FID_INVOLVEDPEOPLE,    //< Involved people list */
  { LINK } ID3FID_LINKEDINFO,        //< Linked information */
  { MCDI } ID3FID_CDID,              //< Music CD identifier */
  { MLLT } ID3FID_MPEGLOOKUP,        //< MPEG location lookup table */
  { OWNE } ID3FID_OWNERSHIP,         //< Ownership frame */
  { PRIV } ID3FID_PRIVATE,           //< Private frame */
  { PCNT } ID3FID_PLAYCOUNTER,       //< Play counter */
  { POPM } ID3FID_POPULARIMETER,     //< Popularimeter */
  { POSS } ID3FID_POSITIONSYNC,      //< Position synchronisation frame */
  { RBUF } ID3FID_BUFFERSIZE,        //< Recommended buffer size */
  { RVA2 } ID3FID_VOLUMEADJ2,        //< Relative volume adjustment (2) */
  { RVAD } ID3FID_VOLUMEADJ,         //< Relative volume adjustment */
  { RVRB } ID3FID_REVERB,            //< Reverb */
  { SEEK } ID3FID_SEEKFRAME,         //< Seek frame */
  { SIGN } ID3FID_SIGNATURE,         //< Signature frame */
  { SYLT } ID3FID_SYNCEDLYRICS,      //< Synchronized lyric/text */
  { SYTC } ID3FID_SYNCEDTEMPO,       //< Synchronized tempo codes */
  { TALB } ID3FID_ALBUM,             //< Album/Movie/Show title */
  { TBPM } ID3FID_BPM,               //< BPM (beats per minute) */
  { TCOM } ID3FID_COMPOSER,          //< Composer */
  { TCON } ID3FID_CONTENTTYPE,       //< Content type */
  { TCOP } ID3FID_COPYRIGHT,         //< Copyright message */
  { TDAT } ID3FID_DATE,              //< Date */
  { TDEN } ID3FID_ENCODINGTIME,      //< Encoding time */
  { TDLY } ID3FID_PLAYLISTDELAY,     //< Playlist delay */
  { TDOR } ID3FID_ORIGRELEASETIME,   //< Original release time */
  { TDRC } ID3FID_RECORDINGTIME,     //< Recording time */
  { TDRL } ID3FID_RELEASETIME,       //< Release time */
  { TDTG } ID3FID_TAGGINGTIME,       //< Tagging time */
  { TIPL } ID3FID_INVOLVEDPEOPLE2,   //< Involved people list */
  { TENC } ID3FID_ENCODEDBY,         //< Encoded by */
  { TEXT } ID3FID_LYRICIST,          //< Lyricist/Text writer */
  { TFLT } ID3FID_FILETYPE,          //< File type */
  { TIME } ID3FID_TIME,              //< Time */
  { TIT1 } ID3FID_CONTENTGROUP,      //< Content group description */
  { TIT2 } ID3FID_TITLE,             //< Title/songname/content description */
  { TIT3 } ID3FID_SUBTITLE,          //< Subtitle/Description refinement */
  { TKEY } ID3FID_INITIALKEY,        //< Initial key */
  { TLAN } ID3FID_LANGUAGE,          //< Language(s) */
  { TLEN } ID3FID_SONGLEN,           //< Length */
  { TMCL } ID3FID_MUSICIANCREDITLIST,//< Musician credits list */
  { TMED } ID3FID_MEDIATYPE,         //< Media type */
  { TMOO } ID3FID_MOOD,              //< Mood */
  { TOAL } ID3FID_ORIGALBUM,         //< Original album/movie/show title */
  { TOFN } ID3FID_ORIGFILENAME,      //< Original filename */
  { TOLY } ID3FID_ORIGLYRICIST,      //< Original lyricist(s)/text writer(s) */
  { TOPE } ID3FID_ORIGARTIST,        //< Original artist(s)/performer(s) */
  { TORY } ID3FID_ORIGYEAR,          //< Original release year */
  { TOWN } ID3FID_FILEOWNER,         //< File owner/licensee */
  { TPE1 } ID3FID_LEADARTIST,        //< Lead performer(s)/Soloist(s) */
  { TPE2 } ID3FID_BAND,              //< Band/orchestra/accompaniment */
  { TPE3 } ID3FID_CONDUCTOR,         //< Conductor/performer refinement */
  { TPE4 } ID3FID_MIXARTIST,         //< Interpreted, remixed, or otherwise modified by */
  { TPOS } ID3FID_PARTINSET,         //< Part of a set */
  { TPRO } ID3FID_PRODUCEDNOTICE,    //< Produced notice */
  { TPUB } ID3FID_PUBLISHER,         //< Publisher */
  { TRCK } ID3FID_TRACKNUM,          //< Track number/Position in set */
  { TRDA } ID3FID_RECORDINGDATES,    //< Recording dates */
  { TRSN } ID3FID_NETRADIOSTATION,   //< Internet radio station name */
  { TRSO } ID3FID_NETRADIOOWNER,     //< Internet radio station owner */
  { TSIZ } ID3FID_SIZE,              //< Size */
  { TSOA } ID3FID_ALBUMSORTORDER,    //< Album sort order */
  { TSOP } ID3FID_PERFORMERSORTORDER,//< Performer sort order */
  { TSOT } ID3FID_TITLESORTORDER,    //< Title sort order */
  { TSRC } ID3FID_ISRC,              //< ISRC (international standard recording code) */
  { TSSE } ID3FID_ENCODERSETTINGS,   //< Software/Hardware and settings used for encoding */
  { TSST } ID3FID_SETSUBTITLE,       //< Set subtitle */
  { TXXX } ID3FID_USERTEXT,          //< User defined text information */
  { TYER } ID3FID_YEAR,              //< Year */
  { UFID } ID3FID_UNIQUEFILEID,      //< Unique file identifier */
  { USER } ID3FID_TERMSOFUSE,        //< Terms of use */
  { USLT } ID3FID_UNSYNCEDLYRICS,    //< Unsynchronized lyric/text transcription */
  { WCOM } ID3FID_WWWCOMMERCIALINFO, //< Commercial information */
  { WCOP } ID3FID_WWWCOPYRIGHT,      //< Copyright/Legal infromation */
  { WOAF } ID3FID_WWWAUDIOFILE,      //< Official audio file webpage */
  { WOAR } ID3FID_WWWARTIST,         //< Official artist/performer webpage */
  { WOAS } ID3FID_WWWAUDIOSOURCE,    //< Official audio source webpage */
  { WORS } ID3FID_WWWRADIOPAGE,      //< Official internet radio station homepage */
  { WPAY } ID3FID_WWWPAYMENT,        //< Payment */
  { WPUB } ID3FID_WWWPUBLISHER,      //< Official publisher webpage */
  { WXXX } ID3FID_WWWUSER,           //< User defined URL link */
  {      } ID3FID_METACRYPTO,        //< Encrypted meta frame (id3v2.2.x) */
  {      } ID3FID_METACOMPRESSION,   //< Compressed meta frame (id3v2.2.1) */
  { >>>> } ID3FID_LASTFRAMEID        //< Last field placeholder */
);

  ID3Tag = pointer;
  ID3TagIterator = pointer;
  ID3TagConstIterator = pointer;
  ID3Frame = pointer;
  ID3Field = pointer;

  ID3_Err = integer;
  index_t = integer;
  size_t = integer;
  flags_t = word;

  ID3TagHeader = array[0..ID3_TAGHEADERSIZE-1] of byte;

  // tag wrappers
  function  ID3Tag_New : ID3Tag; stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_Delete(const tag:Id3Tag); stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_Clear(const tag:Id3Tag); stdcall; external 'ID3Lib.dll';
  function  ID3Tag_HasChanged(const tag:Id3Tag) : boolean; stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_SetUnsync(const tag:Id3Tag; unsync:boolean); stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_SetExtendedHeader( tag:ID3Tag; ext:boolean); stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_SetPadding( tag:ID3Tag; pad:boolean); stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_AddFrame( tag:ID3Tag; const frame:ID3Frame); stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_AttachFrame( tag:ID3Tag; frame:ID3Frame); stdcall; external 'ID3Lib.dll';
  procedure ID3Tag_AddFrames( tag:ID3Tag; const frames:ID3Frame; num:integer); stdcall; external 'ID3Lib.dll';
  function  ID3Tag_RemoveFrame( tag:ID3Tag; const frame:ID3Frame):ID3Frame; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_Parse( tag:ID3Tag; header:ID3TagHeader; buffer:pointer):ID3_Err; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_Link( tag:ID3Tag; const fileName:string):size_t; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_Update( tag:ID3Tag):ID3_Err; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_UpdateByTagType( tag:ID3Tag; tagtype:flags_t):ID3_Err; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_Strip( tag:ID3Tag; ulTagFlags:flags_t):ID3_Err; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_FindFrameWithID( const tag:ID3Tag; id:ID3_FrameID):ID3Frame; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_FindFrameWithINT( const tag:ID3Tag; id:ID3_FrameID; fld:ID3_FieldID; data:longint):ID3Frame; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_FindFrameWithASCII( const tag:ID3Tag; id:ID3_FrameID; fld:ID3_FieldID; const data:string):ID3Frame; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_FindFrameWithUNICODE( const tag:ID3Tag; id:ID3_FrameID; fld:ID3_FieldID; const data:widestring):ID3Frame; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_NumFrames( const tag:ID3Tag):size_t; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_HasTagType( const tag:ID3Tag; tagtype:ID3_TagType):boolean; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_CreateIterator( tag:ID3Tag):ID3TagIterator; stdcall; external 'ID3Lib.dll';
  function  ID3Tag_CreateConstIterator( const tag:ID3Tag):ID3TagConstIterator; stdcall; external 'ID3Lib.dll';

  procedure ID3TagIterator_Delete( tagiter:ID3TagIterator); stdcall; external 'ID3Lib.dll';
  function  ID3TagIterator_GetNext( tagiter:ID3TagIterator):ID3Frame; stdcall; external 'ID3Lib.dll';
  procedure ID3TagConstIterator_Delete( tagiter:ID3TagConstIterator); stdcall; external 'ID3Lib.dll';
  function  ID3TagConstIterator_GetNext( tagiter:ID3TagConstIterator):ID3Frame; stdcall; external 'ID3Lib.dll';

  // frame wrappers 
  function  ID3Frame_New:ID3Frame; stdcall; external 'ID3Lib.dll';
  function  ID3Frame_NewID( id:ID3_FrameID):ID3Frame; stdcall; external 'ID3Lib.dll';
  procedure ID3Frame_Delete( frame:ID3Frame); stdcall; external 'ID3Lib.dll';
  procedure ID3Frame_Clear( frame:ID3Frame); stdcall; external 'ID3Lib.dll';
  procedure ID3Frame_SetID( frame:ID3Frame; id:ID3_FrameID); stdcall; external 'ID3Lib.dll';
  function  ID3Frame_GetID( const frame:ID3Frame):ID3_FrameID; stdcall; external 'ID3Lib.dll';
  function  ID3Frame_GetField( const frame:ID3Frame; name:ID3_FieldID):ID3Field; stdcall; external 'ID3Lib.dll';
  procedure ID3Frame_SetCompression( frame:ID3Frame; comp:boolean); stdcall; external 'ID3Lib.dll';
  function  ID3Frame_GetCompression( frame:ID3Frame):boolean; stdcall; external 'ID3Lib.dll';

  // field wrappers
  procedure ID3Field_Clear( field:ID3Field); stdcall; external 'ID3Lib.dll';
  function  ID3Field_Size( const field:ID3Field):size_t; stdcall; external 'ID3Lib.dll';
  function  ID3Field_GetNumTextItems( const field:ID3Field):size_t; stdcall; external 'ID3Lib.dll';
  procedure ID3Field_SetINT( field:ID3Field; data:longint); stdcall; external 'ID3Lib.dll';
  function  ID3Field_GetINT( const field:ID3Field):longint; stdcall; external 'ID3Lib.dll';
  procedure ID3Field_SetUNICODE( field:ID3Field; const unistr:widestring); stdcall; external 'ID3Lib.dll';
  function  ID3Field_GetUNICODE( const field:ID3Field; buffer:widestring; maxChars:size_t):size_t; stdcall; external 'ID3Lib.dll';
  function  ID3Field_GetUNICODEItem( const field:ID3Field; buffer:widestring; maxChars:size_t; itemNum:index_t):size_t; stdcall; external 'ID3Lib.dll';
  procedure ID3Field_AddUNICODE( field:ID3Field; const unistring:widestring); stdcall; external 'ID3Lib.dll';
  procedure ID3Field_SetASCII( field:ID3Field; const str:string); stdcall; external 'ID3Lib.dll';
  function  ID3Field_GetASCII( const field:ID3Field; buffer:string; maxChars:size_t):size_t; stdcall; external 'ID3Lib.dll';
  function  ID3Field_GetASCIIItem( const field:ID3Field; buffer:string; maxChars:size_t; itemNum:index_t):size_t; stdcall; external 'ID3Lib.dll';
  procedure ID3Field_AddASCII( field:ID3Field; const str:string); stdcall; external 'ID3Lib.dll';
  procedure ID3Field_SetBINARY( field:ID3Field; const data:pointer; size:size_t); stdcall; external 'ID3Lib.dll';
  procedure ID3Field_GetBINARY( field:ID3Field; buffer:pointer; buffLength:size_t); stdcall; external 'ID3Lib.dll';
  procedure ID3Field_FromFile( field:ID3Field; const fileName:string); stdcall; external 'ID3Lib.dll';
  procedure ID3Field_ToFile( const field:ID3Field; const fileName:string); stdcall; external 'ID3Lib.dll';

  // Deprecated
  // ID3_C_EXPORT void        ID3Tag_SetCompression       (ID3Tag *tag, bool comp);

  // Delphi specific functions follow
  function ID3Field_GetAsciiD( const field:ID3Field; maxChars:size_t):string;
  function ID3Field_GetAsciiItemD( const field:ID3Field; maxChars:size_t; itemNum:index_t):string;
  function ID3Field_GetUNICODED( const field:ID3Field; maxChars:size_t):widestring;
  function ID3Field_GetUNICODEItemD( const field:ID3Field; maxChars:size_t; itemNum:index_t):widestring;

implementation

uses
  Utils;

function ID3Field_GetAsciiD( const field:ID3Field; maxChars:size_t):string;
var
  s : string;
  i : integer;
begin
  SetLength( s, maxChars+1);
  ID3Field_GetAscii( field, s, maxChars);
  i := pos(#0, s)-1;
  if (i<0) or (i>maxChars+1) then
    i:=0;
  SetLength( s, i);
  result := s;
end;

function ID3Field_GetAsciiItemD( const field:ID3Field; maxChars:size_t; itemNum:index_t):string;
var
  s : string;
  i : integer;
begin
  SetLength( s, maxChars+1);
  ID3Field_GetAsciiItem( field, s, maxChars, itemNum);
  i := pos(#0, s)-1;
  if (i<0) or (i>maxChars+1) then
    i:=0;
  SetLength( s, i);
  result := s;
end;

function ID3Field_GetUNICODED( const field:ID3Field; maxChars:size_t):widestring;
var
  ws : widestring;
  i : integer;
begin
  SetLength( ws, maxChars+1);
  ID3Field_GetUNICODE( field, ws, maxChars);
  i := pos(#0, ws)-1;
  if (i<0) or (i>maxChars+1) then
    i:=0;
  SetLength( ws, i);
  RotateWideString( ws);
  result := ws;
end;

function ID3Field_GetUNICODEItemD( const field:ID3Field; maxChars:size_t; itemNum:index_t):widestring;
var
  ws : widestring;
  i : integer;
begin
  SetLength( ws, maxChars+1);
  ID3Field_GetUNICODEItem( field, ws, maxChars, itemNum);
  i := pos(#0, ws)-1;
  if (i<0) or (i>maxChars+1) then
    i:=0;
  SetLength( ws, i);
  result := ws; 
end;

end.
