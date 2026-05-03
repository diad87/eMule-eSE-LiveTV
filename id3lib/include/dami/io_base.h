// -*- C++ -*-
// $Id: io_base.h,v 1.2 2002/09/13 14:09:55 t1mpy Exp $

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

#ifndef _ID3LIB_READER_H_
#define _ID3LIB_READER_H_

#include "globals.h"

namespace dami
{
  namespace io
  {
    typedef uint32 size_type;
    typedef uint8  char_type;
    typedef uint32 pos_type;
    typedef  int32 off_type;
    typedef  int16 int_type;
    const int_type END_OF_IO = -1;

    class Base
    {
     public:
      virtual void close() = 0;

      virtual pos_type getBeg() { return static_cast<pos_type>(0); }

      virtual pos_type getEnd() { return static_cast<pos_type>(-1); }

      virtual pos_type getCur() = 0;

      virtual pos_type setCur(pos_type pos) = 0;

      virtual size_type remainingBytes()
      {
        pos_type end = this->getEnd(), cur = this->getCur();
        if (end == pos_type(-1))
        {
          return size_type(-1);
        }

        if (end >= cur)
        {
          return end - cur;
        }

        return 0;
      }

      virtual bool atEnd() { return this->getCur() >= this->getEnd(); }
    };

    class Reader : virtual public Base
    {
      virtual int_type readChar()
      {
        if (this->atEnd())
        {
          return END_OF_IO;
        }
        char_type ch;
        this->readChars(&ch, 1);
        return ch;
      }

      virtual int_type peekChar() = 0;

      virtual size_type readChars(char_type buf[], size_type len) = 0;
      virtual size_type readChars(char buf[], size_type len)
      {
        return this->readChars(reinterpret_cast<char_type *>(buf), len);
      }

      virtual size_type skipChars(size_type len)
      {
        const size_type SIZE = 1024;
        char_type bytes[SIZE];
        size_type remaining = len;
        while (!this->atEnd() && remaining > 0)
        {
          remaining -= this->readChars(bytes, (remaining < SIZE ? remaining : SIZE));
        }
        return len - remaining;
      }


    };

    class Writer : virtual class Base
    {
      virtual void flush() = 0;

      virtual int_type writeChar(char_type ch)
      {
        if (this->atEnd())
        {
          return END_OF_WRITER;
        }
        this->writeChars(&ch, 1);
        return ch;
      }

      virtual size_type writeChars(const char_type buf[], size_type len) = 0;
      virtual size_type writeChars(const char buf[], size_type len)
      {
        return this->writeChars(reinterpret_cast<const char_type *>(buf), len);
      }

    };

    class File : public Readable, public Writable
    {
      String _fileName;
     public:

    };
  }
