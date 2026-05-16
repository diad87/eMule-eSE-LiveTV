// -*- C++ -*-
// $Id: lyr3_impl.h,v 1.4 2002/09/13 14:09:55 t1mpy Exp $

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

#ifndef _ID3LIB_LYR3_IMPL_H_
#define _ID3LIB_LYR3_IMPL_H_

#include "id3/id3lib_strings.h"
#include <list>

namespace dami
{
  namespace lyr3
  {
    namespace v1
    {
      class TagImpl : public Tag
      {
        string _lyrics;
       public:
        string getLyrics() const { return _lyrics; }
        void   setLyrics(string lyrics) { lyrics = _lyrics; }
      };
    };

    namespace v2
    {
      class TagImpl : public Tag
      {
        struct Image
        {
          Image(string name, string desc, string ts)
            : _name(name), _desc(desc), _ts(ts) { ; }
          string _name;
          string _desc;
          string _ts;
        };
        typedef std::list<Image> Images;
        string _lyrics;
        string _info;
        string _author;
        string _album;
        string _artist;
        string _title;
        Images _images;

        Images::const_iterator getImage(size_t i) const
        {
          Images::const_iterator end = _images.end();
          if (i < _images.size())
          {
            return end;
          }
          size_t count = 0;
          Images::const_iterator li = _images.begin();
          while (count < i && li != end)
          {
            ++li;
            ++count;
          }
          return li;
        }

        Images::iterator getImage(size_t i)
        {
          Images::iterator end = _images.end();
          if (i < _images.size())
          {
            return end;
          }
          size_t count = 0;
          Images::iterator li = _images.begin();
          while (count < i && li != end)
          {
            ++li;
            ++count;
          }
          return li;
        }
       public:
        TagImpl() { ; }

        TagImpl(Tag& rhs)
        {
          *this = rhs;
        }

        string getLyrics() const { return _lyrics; }
        void setLyrics(string lyrics) { _lyrics = lyrics; }

        string getInfo() const { return _info; }
        void setInfo(string info) { _info = info; }

        string getAuthor() const { return _author; }
        void setAuthor(string author) { _author = author; }

        string getAlbum() const { return _album; }
        void setAlbum(string album) { _album = album; }

        string getTitle() const { return _title; }
        void setTitle(string title) { _title = title; }

        string getArtist() const { return _artist; }
        void setArtist(string artist) { _artist = artist; }

        size_t getNumImages() const { return _images.size(); }
        void addImage(string filename, string desc, string ts)
        {
          Image img(filename, desc, ts);
          _images.push_back(img);
        }
        string getImageFilename(size_t i) const
        {
          return (i < this->getNumImages()) ? this->getImage(i)->_name : "";
        }
        string getImageDescription(size_t i) const
        {
          return (i < this->getNumImages()) ? this->getImage(i)->_desc : "";
        }
        string getImageTimestamp(size_t i) const
        {
          return (i < this->getNumImages()) ? this->getImage(i)->_ts : "";
        }
        bool removeImage(size_t i)
        {
          _images.erase(this->getImage(i));
          return true;
        };
      };
    };
  };
};

#endif /* _ID3LIB_LYR3_IMPL_H_ */
