// -*- C++ -*-
// $Id: mm.h,v 1.3 2002/09/13 14:09:55 t1mpy Exp $

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

#ifndef _ID3LIB_MM_H_
#define _ID3LIB_MM_H_

#include "id3/id3lib_strings.h"

namespace dami
{
  namespace mm
  {
    class Tag
    {
     public:

      Tag& operator=(const Tag& rhs)
      {
        if (this != &rhs)
        {
          this->setImageType(rhs.getImageType());
          this->setImageBinary(rhs.getImageBinary());
          this->setTitle(rhs.getTitle());
          this->setAlbum(rhs.getAlbum());
          this->setArtist(rhs.getArtist());
          this->setGenre(rhs.getGenre());
          this->setTempo(rhs.getTempo());
          this->setMood(rhs.getMood());
          this->setSituation(rhs.getSituation());
          this->setPreference(rhs.getPreference());
          this->setDuration(rhs.getDuration());
          this->setPlayCounter(rhs.getPlayCounter());
          this->setOrigFilename(rhs.getOrigFilename());
          this->setSerial(rhs.getSerial());
          this->setTrack(rhs.getTrack());
          this->setNotes(rhs.getNotes());
          this->setArtistBio(rhs.getArtistBio());
          this->setLyrics(rhs.getLyrics());
          this->setArtistURL(rhs.getArtistURL());
          this->setBuyURL(rhs.getBuyURL());
          this->setEmail(rhs.getEmail());
        }
        return *this;
      }

      virtual string getImageType() const = 0;
      virtual void setImageType(string) = 0;

      virtual bstring getImageBinary() const = 0;
      virtual void setImageBinary(bstring) = 0;

      virtual string getTitle() const = 0;
      virtual void setTitle(string) = 0;

      virtual string getAlbum() const = 0;
      virtual void setAlbum(string) = 0;

      virtual string getArtist() const = 0;
      virtual void setArtist(string) = 0;

      virtual string getGenre() const = 0;
      virtual void setGenre(string) = 0;

      virtual string getTempo() const = 0;
      virtual void setTempo(string) = 0;

      virtual string getMood() const = 0;
      virtual void setMood(string) = 0;

      virtual string getSituation() const = 0;
      virtual void setSituation(string) = 0;

      virtual string getPreference() const = 0;
      virtual void setPreference(string) = 0;

      virtual string getDuration() const = 0;
      virtual unsigned short getDurationMin() const = 0;
      virtual unsigned short getDurationSec() const = 0;
      virtual void setDuration(string) = 0;
      virtual void setDurationMin(unsigned short) = 0;
      virtual void setDurationSec(unsigned short) = 0;

      virtual uint32 getPlayCounter() const = 0;;
      virtual void setPlayCounter(uint32) = 0;;

      virtual string getOrigFilename() const = 0;
      virtual void setOrigFilename(string) = 0;

      virtual string getSerial() const = 0;
      virtual void setSerial(string) = 0;

      virtual unsigned short getTrack() const = 0;
      virtual void setTrack(unsigned short track) = 0;

      virtual string getNotes() const = 0;
      virtual void setNotes(string) = 0;

      virtual string getArtistBio() const = 0;
      virtual void setArtistBio(string) = 0;

      virtual string getLyrics() const = 0;
      virtual void setLyrics(string) = 0;

      virtual string getArtistURL() const = 0;
      virtual void setArtistURL(string) = 0;

      virtual string getBuyURL() const = 0;
      virtual void setBuyURL(string) = 0;

      virtual string getEmail() const = 0;
      virtual void setEmail(string) = 0;
    };
  };
};

#endif /* _ID3LIB_MM_H_ */
