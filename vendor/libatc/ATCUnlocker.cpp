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


#include "ATCUnlocker.h"
#include "ATCUnlocker_impl.h"


ATCUnlocker::ATCUnlocker() :

impl_(NULL)

{
	impl_ = new ATCUnlocker_impl();
}

ATCUnlocker::~ATCUnlocker()
{
	if (impl_)
	{
		delete impl_;
		impl_ = NULL;
	}
}

ATCResult ATCUnlocker::open(istream *src, const char key[ATC_KEY_SIZE])
{
	return impl_->open(src, key);
}

ATCResult ATCUnlocker::close()
{
	return impl_->close();
}

size_t ATCUnlocker::getEntryLength() const
{
	return impl_->getEntryLength();
}

ATCResult ATCUnlocker::getEntry(ATCFileEntry *entry, size_t index)
{
	return impl_->getEntry(entry, index);
}

ATCResult ATCUnlocker::extractFileData(ostream *dst, istream *src, size_t length)
{
	return impl_->extractFileData(dst, src, length);
}

ATCResult ATCUnlocker::dumpRawDecryptedBody(ostream *dst, istream *src)
{
	return impl_->dumpRawDecryptedBody(dst, src);
}

int32_t ATCUnlocker::data_version() const
{
	return impl_->data_version();
}

char ATCUnlocker::data_sub_version() const
{
	return impl_->data_sub_version();
}

int32_t ATCUnlocker::algorism_type() const
{
	return impl_->algorism_type();
}

char ATCUnlocker::passwd_try_limit() const
{
	return impl_->passwd_try_limit();
}

bool ATCUnlocker::self_destruction() const
{
	return impl_->self_destruction();
}

bool ATCUnlocker::broken() const
{
	return impl_->broken();
}
