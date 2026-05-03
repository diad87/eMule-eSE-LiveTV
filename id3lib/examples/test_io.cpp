// $Id: test_io.cpp,v 1.7 2009/08/31 22:01:50 nagilo Exp $

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

#include <id3/readers.h>
#include <id3/writers.h>
#include <id3/io_decorators.h>
#include <id3/io_helpers.h>
#include <id3/io_strings.h>
#include <id3/utils.h>

using namespace dami;
using namespace std;

int
main(size_t argc, const char** argv)
{
  ID3D_INIT_DOUT();
  ID3D_INIT_WARNING();
  ID3D_INIT_NOTICE();

  ID3_IStreamReader isr(cin);
  BString orig = io::readAllBinary(isr);

  cout << "input size:    " << orig.size() << endl;

  cout << endl;

  cout << "=== Testing Synchronization ===" << endl;
  BString synced;

  {
    io::BStringReader sr(orig);
    io::UnsyncedReader ur(sr);

    synced = io::readAllBinary(ur);
  }

  cout << "synced size:   " << synced.size() << endl;

  BString unsynced;

  {
    io::BStringWriter sw(unsynced);
    io::UnsyncedWriter uw(sw);

    uw.writeChars(synced.data(), synced.size());
  }

  cout << "unsynced size: " << unsynced.size() << endl;

  BString resynced;

  {
    io::BStringReader sr(unsynced);
    io::UnsyncedReader ur(sr);

    resynced = io::readAllBinary(ur);
  }

  cout << "resynced size: " << resynced.size() << endl;

  if (unsynced == orig)
  {
    cout << "orig == unsynced" << endl;
  }
  else
  {
    cout << "orig != unsynced" << endl;
  }
  if (synced == resynced)
  {
    cout << "synced == resynced" << endl;
  }
  else
  {
    cout << "synced != resynced" << endl;
  }

  cout << endl;
  cout << "=== Testing Trailing Spaces ===" << endl;

  String text;

  {
    io::StringWriter sw(text);
    io::writeTrailingSpaces (sw, "hello, world", 50);
  }

  cout << "new text  = \"" << text << "\"" << endl;

  String origText;

  {
    io::StringReader sr(text);
    origText = io::readTrailingSpaces(sr, 100);
  }

  cout << "orig text = \"" << origText << "\"" << endl;

  cout << endl;
  cout << "=== Testing Binary Numbers ===" << endl;

  String number;

  {
    io::StringWriter sw(number);
    io::writeBENumber(sw, 1234567890, 4);
  }

  cout << "binary number:";
  for (size_t i = 0; i < number.size(); ++i)
  {
    cout << " 0x" << hex << (size_t) (0xFF & number[i]) << dec;
  }
  cout << endl;

  size_t val;

  {
    io::StringReader sr(number);
    val = io::readBENumber(sr, 4);
  }

  cout << "orig number: " << val << endl;

  cout << endl;
  cout << "=== Testing Compression ===" << endl;

  String compressed;
  size_t origSize = orig.size();
  cout << "origSize = " << origSize << endl;


  {
    io::StringWriter sw(compressed);
    io::CompressedWriter cw(sw);
    cw.writeChars(orig.data(), orig.size());
    cw.flush();
    if (origSize != cw.getOrigSize())
    {
      origSize = cw.getOrigSize();
      cout << "cw.getOrigSize() = " << origSize << endl;
    }
  }

  cout << "compressed size = " << compressed.size() << endl;

  BString uncompressed;

  if (origSize == 0)
  {
    cout << "no compression" << endl;
  }
  else
  {
    io::StringReader sr(compressed);
    io::CompressedReader cr(sr, origSize);

    uncompressed = io::readAllBinary(cr);
    cout << "uncompressed size = " << uncompressed.size() << endl;
  }

  if (uncompressed.size() == orig.size())
  {
    if (uncompressed == orig)
    {
      cout << "orig == uncompressed" << endl;
    }
    else
    {
      cout << "orig != uncompressed" << endl;
    }
  }

  String ascii;
  ascii.reserve(8192);

  for (size_t i = 0; i < 8192; ++i)
  {
    ascii += 'a' + (i % 26);
  }

  cout << endl;
  cout << "ascii.size() = " << ascii.size() << endl;
  String unicode = dami::convert(ascii, ID3TE_ISO8859_1, ID3TE_UTF16BE);
  cout << "uncicode.size() = " << unicode.size() << endl;
  String ascii_2 = dami::convert(unicode, ID3TE_UTF16BE, ID3TE_ISO8859_1);
  if (ascii != ascii_2)
  {
    cout << "ascii != ascii_2" << endl;
  }
  else
  {
    cout << "ascii == ascii_2" << endl;
  }



  return 0;
}

