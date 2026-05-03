// $Id: test_remove.cpp,v 1.14 2009/08/31 22:01:50 nagilo Exp $

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

#if defined(HAVE_CONFIG_H)
# include "config.h"
#endif

#include "id3/id3lib_streams.h"
#include "id3/tag.h"
#include "id3/misc_support.h"
#include "id3/id3lib_strings.h"

using namespace dami;
using namespace std;

typedef const char* LPCTSTR;

/* CSharedTag is a wrapper I made for some features I need */
/* LPCTSTR means const char * */
size_t RemoveFrame(ID3_Tag& pTag, ID3_FrameID fID, LPCTSTR sDescription)
{
  size_t nCount = 0;
  const ID3_Frame * frame = NULL;

  do {
    if (!sDescription)
    {
      cerr << "*** description is null" << endl;
      frame = pTag.Find(fID);
    }
    else
    {
      cerr << "*** description is \"" << sDescription << "\"" << endl;
      frame = pTag.Find(fID, ID3FN_DESCRIPTION, sDescription);
    }

    if (frame)
    {
      ID3_Field* fld = frame->GetField(ID3FN_TEXT);
      String text(fld->GetRawText(), fld->Size());
      cerr << "*** delete frame with text \"" << text << "\"" << endl;
      /* pTag is an ID3_Tag */
      delete pTag.RemoveFrame(frame);
      nCount++;
    }
  } while (frame != NULL);

  return nCount;
}

int main( int argc, char *argv[])
{
  ID3_Tag tag;
  ID3_Frame frame;

  if (argc == 2)
  {
    tag.Link(argv[1]);
    cerr << "removed " << RemoveFrame(tag, ID3FID_COMMENT, "") << " descriptionless comment frames" << endl;
    tag.Update();

  }
  else
  {
    tag.Link("test-remove.tag");
    tag.Strip(ID3TT_ALL);
    tag.Clear();

    frame.SetID(ID3FID_TITLE);
    frame.GetField(ID3FN_TEXT)->Set("Test title");
    tag.AddFrame(frame);

    frame.SetID(ID3FID_COMPOSER);
    frame.GetField(ID3FN_TEXT)->Set("Test composer");
    tag.AddFrame(frame);

    frame.SetID(ID3FID_BAND);
    frame.GetField(ID3FN_TEXT)->Set("Test band");
    tag.AddFrame(frame);

    frame.SetID(ID3FID_CONDUCTOR);
    frame.GetField(ID3FN_TEXT)->Set("Test conductor");
    tag.AddFrame(frame);

    frame.SetID(ID3FID_COMMENT);
    frame.GetField(ID3FN_LANGUAGE)->Set("eng");
    frame.GetField(ID3FN_TEXT)->Set("Test comment");
    frame.GetField(ID3FN_DESCRIPTION)->Set("A Description");
    tag.AddFrame(frame);

    frame.SetID(ID3FID_COMMENT);
    frame.GetField(ID3FN_LANGUAGE)->Set("eng");
    frame.GetField(ID3FN_TEXT)->Set("Test comment 2");
    frame.GetField(ID3FN_DESCRIPTION)->Set("");
    tag.AddFrame(frame);

    frame.SetID(ID3FID_COMMENT);
    frame.GetField(ID3FN_LANGUAGE)->Set("eng");
    frame.GetField(ID3FN_TEXT)->Set("ID3v1 comment text?");
    frame.GetField(ID3FN_DESCRIPTION)->Set(STR_V1_COMMENT_DESC);
    tag.AddFrame(frame);

    tag.SetPadding(false);
    tag.Update(ID3TT_ID3V2);

    cerr << "removed " << ID3_RemoveArtists(&tag) << " artist frames" << endl;
    tag.Update();
    cerr << "removed " << ID3_RemoveTitles(&tag) << " title frames" << endl;
    tag.Update();
    cerr << "removed " << RemoveFrame(tag, ID3FID_COMMENT, "") << " descriptionless comment frames" << endl;
    tag.Update();
  }

  return 0;
}

