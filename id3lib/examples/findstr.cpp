// $Id: findstr.cpp,v 1.7 2002/09/13 14:04:11 t1mpy Exp $

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

#include "id3/id3lib_streams.h"
#include "id3/tag.h"
#include "id3/misc_support.h"

using std::cout;
using std::endl;

int main(unsigned argc, char* argv[])
{
  ID3D_INIT_DOUT();
  ID3D_INIT_WARNING();
  ID3D_INIT_NOTICE();

  if (argc != 2)
  {
    cout << "Usage: findstr <tagfile>" << endl;
    exit(1);
  }
  ID3_Tag tag(argv[1]);
  ID3_Frame* first = NULL, *frame = NULL;
  while(NULL != (frame = tag.Find(ID3FID_COMMENT, ID3FN_DESCRIPTION, "")))
  {
    if (frame == first)
    {
      break;
    }
    if (first == NULL)
    {
      first = frame;
    }
    char* comment = ID3_GetString(frame, ID3FN_TEXT);
    cout << "*** Found comment w/o description: " << comment << endl;
    delete [] comment;
  }
  return 0;
}

