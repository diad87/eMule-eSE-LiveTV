// -*- C++ -*-
// $Id: v1.h,v 1.3 2002/09/13 14:09:55 t1mpy Exp $

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

#ifndef _ID3LIB_V1_H_
#define _ID3LIB_V1_H_

#include "id3/id3lib_strings.h"

namespace dami
{
  namespace id3
  {
    namespace v1
    {
      class Tag
      {
       public:

        Tag& operator=(const Tag& rhs)
        {
          if (this != &rhs)
          {
            this->setTitle(rhs.getTitle());
            this->setArtist(rhs.getArtist());
            this->setAlbum(rhs.getAlbum());
            this->setYear(rhs.getYear());
            this->setComment(rhs.getComment());
            this->setTrack(rhs.getTrack());
            this->setGenre(rhs.getGenre());
          }
          return *this;
        }

        virtual string getTitle() const = 0;
        virtual void setTitle(string) = 0;

        virtual string getArtist() const = 0;
        virtual void setArtist(string) = 0;

        virtual string getAlbum() const = 0;
        virtual void setAlbum(string) = 0;

        virtual string getComment() const = 0;
        virtual void setComment(string) = 0;

        virtual string getYear() const = 0;
        virtual void setYear(string year) = 0;

        virtual unsigned short getTrack() const = 0;
        virtual void setTrack(unsigned short track) = 0;

        virtual unsigned short getGenre() const = 0;
        virtual void setGenre(unsigned short genre) = 0;
      };
    };
  };
};

#endif /* _ID3LIB_V1_H_ */
