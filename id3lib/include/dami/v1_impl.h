// -*- C++ -*-
// $Id: v1_impl.h,v 1.2 2002/09/13 14:09:55 t1mpy Exp $

// id3lib: a software library for creating and manipulating id3v1/v2 tags
// Copyright 1999, 2000  Scott Thomas Haug
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

#ifndef _ID3LIB_V1_IMPL_H_
#define _ID3LIB_V1_IMPL_H_

#include "v1.h"

namespace dami
{
  namespace id3
  {
    namespace v1
    {
      class TagImpl : public Tag
      {
        string         _title;
        string         _album;
        string         _artist;
        string         _year;
        string         _comment;
        unsigned char  _track;
        unsigned char  _genre;
       public:

        TagImpl() : _track(0), _genre(0xFF) { ; }
        TagImpl(Tag& rhs) { *this = rhs; }

        string getTitle() const { return _title; }
        void setTitle(string title) { _title = title; }

        string getArtist() const { return _artist; }
        void setArtist(string artist) { _artist = artist; }

        string getAlbum() const { return _album; }
        void setAlbum(string album) { _album = album; }

        string getComment() const { return _comment; }
        void setComment(string comment) { _comment = comment; }

        string getYear() const { return _year; }
        void setYear(string year) { year = _year; }

        unsigned short getTrack() const { return _track; }
        void setTrack(unsigned short track) { _track = track; }

        unsigned short getGenre() const { return _genre; }
        void setGenre(unsigned short genre) { _genre = genre; }
      };
    };
  };
};

#endif /* _ID3LIB_V1_IMPL_H_ */
