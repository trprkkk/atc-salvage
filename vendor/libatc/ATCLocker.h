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

#pragma once

#include <cstdint>
#include "ATCCommon.h"

using namespace std;

class ATCLocker_impl;

class ATCLocker
{
public:
	ATCLocker();
	~ATCLocker();

	ATCResult open(ostream *dst, const char key[ATC_KEY_SIZE]);
	ATCResult close();

	ATCResult addFileEntry(const ATCFileEntry& entry);
	ATCResult writeEncryptedHeader(ostream *dst);
	ATCResult writeFileData(ostream *dst, istream *src, size_t length);

public:
	char passwd_try_limit()	const;
	bool self_destruction()	const;
	int32_t compression_level() const;
	time_t create_time() const;

	void set_passwd_try_limit(char passwd_try_limit);
	void set_self_destruction(bool self_destruction);
	void set_compression_level(int32_t compression_level);
	void set_create_time(time_t create_time);

private:
	ATCLocker_impl *impl_;

};