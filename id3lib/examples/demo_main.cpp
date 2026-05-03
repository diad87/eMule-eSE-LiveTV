// $Id: demo_main.cpp,v 1.4 2002/09/13 14:04:11 t1mpy Exp $

// id3lib: a C++ library for creating and manipulating id3v1/v2 tags
// Copyright 2002 Thijmen Klok (thijmen@id3lib.org)

// This library is free software; you can redistribute it and/or modify it
// under the terms of the GNU Library General Public License as published by
// the Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
// License for more details.
//
// You should have received a copy of the GNU Library General Public License
// along with this library; if not, write to the Free Software Foundation,
// Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

// The id3lib authors encourage improvements and optimisations to be sent to
// the id3lib coordinator.  Please see the README file for details on where to
// send such submissions.  See the AUTHORS file for a list of people who have
// contributed to id3lib.  See the ChangeLog file for a list of changes to
// id3lib.  These files are distributed with id3lib at
// http://download.sourceforge.net/id3lib/

#ifndef __DLL


#include "id3/id3lib_streams.h"
#include "id3/tag.h"


void MakeDummyTag(void)
{
  ID3_Tag   myTag("dummy.tag");
  ID3_Frame myFrame[3];

  myFrame[0].SetID(ID3FID_USERTEXT);
  myFrame[0].Field(ID3FN_TEXTENC)     = ID3TE_UTF16;
  myFrame[0].Field(ID3FN_DESCRIPTION) = "example #1";
  myFrame[0].Field(ID3FN_TEXT)        = "This is the text for example #1";

  myFrame[1].SetID(ID3FID_USERTEXT);
  myFrame[1].Field(ID3FN_TEXTENC)     = ID3TE_ISO8859_1;
  myFrame[1].Field(ID3FN_DESCRIPTION) = "example #2";
  myFrame[1].Field(ID3FN_TEXT)        = "This is the text for example #2";

  myFrame[2].SetID(ID3FID_INVOLVEDPEOPLE);
  myFrame[2].Field(ID3FN_TEXTENC)     = ID3TE_ISO8859_1;
  myFrame[2].Field(ID3FN_TEXT).Add("String 1");
  myFrame[2].Field(ID3FN_TEXT).Add("String 2");
  myFrame[2].Field(ID3FN_TEXT).Add("String 3");
  myFrame[2].Field(ID3FN_TEXT).Add("String 4");

  myTag.AddFrames(myFrame, 3);

  //myTag.SetVersion(3, 0);
  myTag.SetUnsync(false);
  myTag.SetExtendedHeader(false);
  myTag.SetCompression(false);
  myTag.SetPadding(false);

  myTag.Strip();
  myTag.Update();

  return;
}


void StripTags(char *file)
{
  ID3_Tag myTag;

  myTag.Link(file);
  myTag.Strip();

  return;
}


void GetTestTag(void)
{
  ID3_Tag  myTag("dummy.tag");
  ID3_Frame *myFrame;

  if (myFrame = myTag.Find(ID3FID_PICTURE))
  {
    cout << "Found a picture frame!\r\n" << endl;

    char *dada = "output.jpg";

    myFrame->Field(ID3FN_DATA).ToFile(dada);
  }

  if (myFrame = myTag.Find(ID3FID_USERTEXT, ID3FN_DESCRIPTION, "example #1"))
  {
    cout << "Found a user text frame!\r\n" << endl;

    char textBuff[1024];

    myFrame->Field(ID3FN_DESCRIPTION).Get(textBuff, 1024);
    cout << "Desc: " << textBuff << endl;

    myFrame->Field(ID3FN_TEXT).Get(textBuff, 1024);
    cout << "Text: " << textBuff << endl;
  }

  for (luint i = 0; i < myTag.NumFrames(); i++)
    if (myFrame = myTag[i])
      cout << "Frame " << i << " has ID " << (luint) myFrame->GetID() << endl;

  return;
}


int main(int argc, char *argv[])
{
  try
  {
    //  CreateDemoTag1();
    //  MakeDummyTag();
    //  GetTestTag();
    StripTags("c:\\temp.mp3");
  }


  catch(ID3_Error err)
  {
    cout << "Error in ID3Lib!" << endl;
    cout << "Error: '" << err.GetErrorDesc() << "'" << endl;
    cout << " File: '" << err.GetErrorFile() << "'" << endl;
    cout << " Line: " << err.GetErrorLine() << endl;
  }

  return 0;
}


#endif


