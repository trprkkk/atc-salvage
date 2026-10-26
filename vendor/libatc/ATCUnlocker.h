/*

Copyright (c) 2013 h2so5 <mail@h2so5.net>

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.

   3. This notice may not be removed or altered from any source
   distribution.

*/
/*
 * NOTE (atc-salvage): This file is an ALTERED version of the file of the same
 * name from libatc by h2so5 (https://github.com/h2so5/libatc). It is NOT the
 * original software. Changes support salvaging damaged archives (a `broken`
 * state flag, keeping partially decoded output on a zlib error, no longer
 * inventing data from stale buffer contents when the input ends early, and a
 * raw body-dump helper). The original copyright and licence notice above is
 * unchanged.
 */


#pragma once

#include <cstdint>

#include "ATCCommon.h"

using namespace std;

class ATCUnlocker_impl;

class ATCUnlocker
{
public:
	ATCUnlocker();
	~ATCUnlocker();

	ATCResult open(istream *src, const char key[ATC_KEY_SIZE]);
	ATCResult close();

	size_t getEntryLength() const;
	ATCResult getEntry(ATCFileEntry *entry, size_t index);
	ATCResult extractFileData(ostream *dst, istream *src, size_t length);
	ATCResult dumpRawDecryptedBody(ostream *dst, istream *src);

public:
	int32_t data_version() const;
	char data_sub_version() const;
	int32_t algorism_type() const;
	char passwd_try_limit() const;
	bool self_destruction() const;
	bool broken() const;

private:
	ATCUnlocker_impl *impl_;

};