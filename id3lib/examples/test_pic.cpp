// $Id: test_pic.cpp,v 1.11 2002/09/13 14:04:11 t1mpy Exp $

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

int main( int argc, char *argv[])
{
  ID3D_INIT_DOUT();
  ID3D_INIT_WARNING();
  ID3D_INIT_NOTICE();

  ID3_Tag tag;
  ID3_Frame frame;

  tag.Link("test-230-picture.tag");
  tag.Strip(ID3TT_ALL);
  tag.Clear();

  frame.SetID(ID3FID_TITLE);
  frame.GetField(ID3FN_TEXT)->Set("Aquarium");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_CONTENTGROUP);
  frame.GetField(ID3FN_TEXT)->Set("Short fraction of 'Carnival of the Animals: A Grand Zoological Fantasy'");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_COMPOSER);
  frame.GetField(ID3FN_TEXT)->Set("Camille Saint-Saëns");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_BAND);
  frame.GetField(ID3FN_TEXT)->Set("Slovakia Radio Symphony Orchestra");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_CONDUCTOR);
  frame.GetField(ID3FN_TEXT)->Set("Ondrej Lenárd");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_COPYRIGHT);
  frame.GetField(ID3FN_TEXT)->Set("1996 HNH international Ltd.");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_CONTENTTYPE);
  frame.GetField(ID3FN_TEXT)->Set("(32)");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_INVOLVEDPEOPLE);
  frame.GetField(ID3FN_TEXT)->Add("Producer");
  frame.GetField(ID3FN_TEXT)->Add("Martin Sauer");
  frame.GetField(ID3FN_TEXT)->Add("Piano");
  frame.GetField(ID3FN_TEXT)->Add("Peter Toperczer");
  tag.AddFrame(frame);

  frame.SetID(ID3FID_PICTURE);
  frame.GetField(ID3FN_MIMETYPE)->Set("image/jpeg");
  frame.GetField(ID3FN_PICTURETYPE)->Set(11);
  frame.GetField(ID3FN_DESCRIPTION)->Set("B/W picture of Saint-Saëns");
  frame.GetField(ID3FN_DATA)->FromFile("composer.jpg");
  tag.AddFrame(frame);

  tag.SetPadding(false);
  tag.SetUnsync(true);
  tag.Update(ID3TT_ID3V2);

  return 0;
}

