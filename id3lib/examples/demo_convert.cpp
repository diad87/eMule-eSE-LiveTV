// $Id: demo_convert.cpp,v 1.17 2009/09/02 09:07:13 nagilo Exp $

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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>
#include "id3/id3lib_streams.h"
#include "id3/tag.h"
#include "demo_convert_options.h"

using std::cout;
using std::endl;

static const char* VERSION_NUMBER = "$Revision: 1.17 $";

void PrintUsage(const char *sName)
{
  cout << "Converts between id3v1 and id3v2 tags of an mp3 file." << endl;
  cout << endl;
  cout << "Will render both types of tag by default.  Only the last" << endl
       << "tag type indicated in the option list will be used.  Non-" << endl
       << "rendered will remain unchanged in the original file.  Will" << endl
       << "also parse and convert Lyrics3 v2.0 frames, but will not" << endl
       << "render them." << endl;
}

void PrintVersion(const char *sName)
{
  size_t nIndex;
  cout << sName << " ";
  for (nIndex = 0; nIndex < strlen(VERSION_NUMBER); nIndex++)
  {
    if (VERSION_NUMBER[nIndex] == ' ')
    {
      break;
    }
  }
  nIndex++;
  for (; nIndex < strlen (VERSION_NUMBER); nIndex++)
  {
    if (VERSION_NUMBER[nIndex] == ' ')
    {
      break;
    }
    cout << VERSION_NUMBER[nIndex];
  }
  cout << endl;
  cout << "Uses " << ID3LIB_FULL_NAME << endl << endl;

  cout << "This program converts and strips ID3v1/1.1 and Lyrics3 v2.0" << endl;
  cout << "tags to ID3v2 tags." << endl << endl;
}

void DisplayTags(ostream &os, luint nTags)
{
  if (!((nTags & ID3TT_ID3V1) || (nTags & ID3TT_ID3V2)))
  {
    os << "no tag";
  }
  if (nTags & ID3TT_ID3V1)
  {
    os << "v1";
  }
  if ((nTags & ID3TT_ID3V1) && (nTags & ID3TT_ID3V2))
  {
    os << " and ";
  }
  if (nTags & ID3TT_ID3V2)
  {
    os << "v2";
  }
}

int main( int argc, char * const argv[])
{
  flags_t ulFlag = ID3TT_ALL;
  gengetopt_args_info args;

  if (cmdline_parser(argc, argv, &args) != 0)
  {
    exit(1);
  }

#if defined ID3_ENABLE_DEBUG
  if (args.warning_flag)
  {
    ID3D_INIT_WARNING();
    ID3D_WARNING ( "warnings turned on" );
  }
  if (args.notice_flag)
  {
    ID3D_INIT_NOTICE();
    ID3D_NOTICE ( "notices turned on" );
  }
#endif

  if (args.v1tag_flag)
  {
    ulFlag = ID3TT_ID3V1;
  }

  if (args.v2tag_flag)
  {
    ulFlag = ID3TT_ID3V2;
  }


  const char* filename = NULL;
  for (size_t i = 0; i < args.inputs_num; ++i)
  {
    filename = args.inputs[i];
    ID3_Tag myTag;

    if (args.strip_given)
    {
      cout << "Stripping ";
    }
    else
    {
      cout << "Converting ";
    }
    cout << filename << ": ";

    myTag.Clear();
    myTag.Link(filename, ID3TT_ALL);
    myTag.SetPadding(args.padding_flag);

    cout << "attempting ";
    DisplayTags(cout, ulFlag);
    luint nTags;

    if (args.strip_flag)
    {
      nTags = myTag.Strip(ulFlag);
      cout << ", stripped ";
    }
    else
    {
      nTags = myTag.Update(ulFlag);
      cout << ", converted ";
    }

    DisplayTags(cout, nTags);
    cout << endl;
  }

  return 0;
}


