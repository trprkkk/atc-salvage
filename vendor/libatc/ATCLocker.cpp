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

#include "ATCLocker.h"
#include "ATCLocker_impl.h"


ATCLocker::ATCLocker() :

impl_(NULL)

{
	impl_ = new ATCLocker_impl();
}

ATCLocker::~ATCLocker()
{
	if (impl_)
	{
		delete impl_;
		impl_ = NULL;
	}
}

ATCResult ATCLocker::open(ostream *dst, const char key[ATC_KEY_SIZE])
{
	return impl_->open(dst, key);
}

ATCResult ATCLocker::close()
{
	return impl_->close();
}

ATCResult ATCLocker::addFileEntry(const ATCFileEntry& entry)
{
	return impl_->addFileEntry(entry);
}

ATCResult ATCLocker::writeEncryptedHeader(ostream *dst)
{
	return impl_->writeEncryptedHeader(dst);
}

ATCResult ATCLocker::writeFileData(ostream *dst, istream *src, size_t length)
{
	return impl_->writeFileData(dst, src, length);
}

char ATCLocker::passwd_try_limit() const
{
	return impl_->passwd_try_limit();
}

bool ATCLocker::self_destruction() const
{
	return impl_->self_destruction();
}

int32_t ATCLocker::compression_level() const
{
	return impl_->compression_level();
}

time_t ATCLocker::create_time() const
{
	return impl_->create_time();
}

void ATCLocker::set_passwd_try_limit(char passwd_try_limit)
{
	impl_->set_passwd_try_limit(passwd_try_limit);
}

void ATCLocker::set_self_destruction(bool self_destruction)
{
	impl_->set_self_destruction(self_destruction);
}

void ATCLocker::set_compression_level(int32_t compression_level)
{
	impl_->set_compression_level(compression_level);
}

void ATCLocker::set_create_time(const time_t create_time)
{
	impl_->set_create_time(create_time);
}