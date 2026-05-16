// $Id: demo_simple.cpp,v 1.2 2002/09/13 14:04:11 t1mpy Exp $

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

#include <id3.h>
#include <stdio.h>

int
main( int argc, char *argv[] )
{
  char *filename = NULL;
  ID3Tag *tag;

  if (argc != 2)
  {
    printf("*** Usage: %s file\n", argv[0]);
    exit (1);
  }
  filename = argv[1];
  printf("*** Reading %s\n", filename);

  if ((tag = ID3Tag_New()) != NULL)
  {
    ID3Frame *frame;

    (void) ID3Tag_Link(tag, filename);
    if ((frame = ID3Tag_FindFrameWithID(tag, ID3FID_TITLE)) != NULL)
    {
      ID3Field *field;
      if ((field = ID3Frame_GetField(frame, ID3FN_TEXT)) != NULL)
      {
        char title[1024];
        (void) ID3Field_GetASCII(field, title, 1024);
        printf("Title: %s\n", title);
      }
      else
      {
        printf("Didn't get the field\n");
      }
    }
    else
    {
      printf("Didn't get the frame\n");
    }

    if ((frame = ID3Tag_FindFrameWithID(tag, ID3FID_LEADARTIST)) != NULL)
    {
      ID3Field *field;
      if ((field = ID3Frame_GetField(frame, ID3FN_TEXT)) != NULL)
      {
        char artist[1024];
        (void) ID3Field_GetASCII(field, artist, 1024);
        printf("Artist: %s\n", artist);
      }
      else
      {
        printf("Didn't get the field\n");
      }
    }
    else
    {
      printf("Didn't get the frame\n");
    }

    if ((frame = ID3Tag_FindFrameWithID(tag, ID3FID_ALBUM)) != NULL)
    {
      ID3Field *field;
      if ((field = ID3Frame_GetField(frame, ID3FN_TEXT)) != NULL)
      {
        char album[1024];
        (void) ID3Field_GetASCII(field, album, 1024);
        printf("Album: %s\n", album);
      }
      else
      {
        printf("Didn't get the field\n");
      }
    }
    else
    {
      printf("Didn't get the frame\n");
    }
  }
  else
  {
    printf("Didn't get the tag\n");
  }
  exit (0);
}
