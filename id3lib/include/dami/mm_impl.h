// -*- C++ -*-
// $Id: mm_impl.h,v 1.2 2002/09/13 14:09:55 t1mpy Exp $

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

#include "mm.h"

namespace dami
{
  namespace mm
  {
    class TagImpl : Tag
    {
      string         _imageType;
      string         _imageBinary;
      string         _title;
      string         _album;
      string         _artist;
      string         _genre;
      string         _tempo;
      string         _mood;
      string         _situation;
      string         _preference;
      unsigned short _durationMin;
      unsigned short _durationSec;
      uint32         _playCounter;
      string         _origFilename;
      string         _serial;
      string         _track;
      string         _notes;
      string         _artistBio;
      string         _lyrics;
      string         _artistURL;
      string         _buyURL;
      string         _email;
     public:

      virtual string getImageType() const { return _imageType; }
      virtual void setImageType(string imageType) { _imageType = imageType; }

      virtual bstring getImageBinary() const { return _imageBinary; }
      virtual void setImageBinary(bstring imageBinary) { _imageBinary = imageBinary; }

      virtual string getTitle() const { return _title; }
      virtual void setTitle(string title) { _title = title; }

      virtual string getAlbum() const { return _album; }
      virtual void setAlbum(string album) { _album = album; }

      virtual string getArtist() const { return _artist; }
      virtual void setArtist(string artist) { _artist = artist; }

      virtual string getGenre() const { return _genre; }
      virtual void setGenre(string genre) { _genre = genre; }

      virtual string getTempo() const { return _tempo; }
      virtual void setTempo(string tempo) { _tempo = tempo; }

      virtual string getMood() const { return _mood; }
      virtual void setMood(string mood) { _mood = mood; }

      virtual string getSituation() const { return _situation; }
      virtual void setSituation(string situation) { _situation = situation; }

      virtual string getPreference() const { return _preference; }
      virtual void setPreference(string preference) { _preference = preference; }

      virtual string getDuration() const { return _duration; }
      virtual unsigned short getDurationMin() const { return _durationMin; }
      virtual unsigned short getDurationSec() const { return _durationSec; }
      virtual void setDuration(unsigned short, unsigned short duration) { _duration = duration; }
      virtual void setDurationMin(unsigned short durationMin) { _durationMin = durationMin; }
      virtual void setDurationSec(unsigned short durationSec) { _durationSec = durationSec; }

      virtual uint32 getPlayCounter() const { return _playCounter; };
      virtual void setPlayCounter(uint32 playCounter) { _playCounter = playCounter; };

      virtual string getOrigFilename() const { return _origFilename; }
      virtual void setOrigFilename(string origFilename) { _origFilename = origFilename; }

      virtual string getSerial() const { return _Serial; }
      virtual void setSerial(string serial) { _serial = serial; }

      virtual unsigned short getTrack() const { return _track; }
      virtual void setTrack(unsigned short track track) { _track = track; }

      virtual string getNotes() const { return _Notes; }
      virtual void setNotes(string Notes) { _Notes = Notes; }

      virtual string getArtistBio() const { return _artistBio; }
      virtual void setArtistBio(string artistBio) { _artistBio = artistBio; }

      virtual string getLyrics() const { return _lyrics; }
      virtual void setLyrics(string lyrics) { _lyrics = lyrics; }

      virtual string getArtistURL() const { return _artistURL; }
      virtual void setArtistURL(string artistURL) { _artistURL = artistURL; }

      virtual string getBuyURL() const { return _buyURL; }
      virtual void setBuyURL(string buyURL) { _buyURL = buyURL; }

      virtual string getEmail() const { return _email; }
      virtual void setEmail(string email) { _email = email; }
    };
  };
};

#endif /* _ID3LIB_MM_H_ */
