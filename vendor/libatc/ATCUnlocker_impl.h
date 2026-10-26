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


#include <cassert>
#include <ctime>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

#include <zlib.h>

#include "Rijndael.h"
#include "blowfish.h"

#include "ATCCommon.h"
#include "ATCUnlocker.h"

#ifdef USE_CLI
	#using<system.dll>
	using namespace System;
	using namespace System::IO;
	using namespace System::Text;
#endif

#define PASS_FOOTER "_AttacheCase-M.Hibara"

class ATCUnlocker_impl
{
public:
	ATCUnlocker_impl();
	~ATCUnlocker_impl();

	ATCResult open(istream *src, const char key[ATC_KEY_SIZE]);
	ATCResult close();

	size_t getEntryLength() const;
	ATCResult getEntry(ATCFileEntry *entry, size_t index);
	ATCResult extractFileData(ostream *dst, istream *src, size_t length);

	// --- salvage-mode addition ---
	// Decrypts every remaining 32-byte body block from the current stream
	// position through to the end of the archive's body, writing the raw
	// decrypted bytes to dst with NO zlib involved at all. Because AES/
	// Rijndael-CBC self-synchronizes after two blocks, this recovers the
	// correct compressed byte stream everywhere except the handful of
	// blocks that were actually corrupted on disk -- even though zlib
	// itself can no longer make sense of the sequence once it hits the
	// bad spot. Padding is NOT stripped from the final block (the exact
	// byte offset matters for downstream bitstream-resync work).
	ATCResult dumpRawDecryptedBody(ostream *dst, istream *src);

#ifdef USE_CLI
	ATCResult open(Stream ^src, array<System::Byte, 1> ^key);
	ATCResult extractFileData(Stream ^dst, Stream ^src, size_t length);
#endif

public:
	int32_t data_version() const;
	char data_sub_version() const;
	int32_t algorism_type() const;
	char passwd_try_limit() const;
	bool self_destruction() const;

	// --- salvage-mode addition ---
	// Becomes true once the compressed/encrypted stream could no longer be
	// decoded (corruption, truncation, etc). Once true, any bytes already
	// produced for the *current* extractFileData() call have still been
	// written to dst; do not call extractFileData() again after this is set.
	bool broken() const { return broken_; }

private:
	void decryptBufferRijndael(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE]);
	void decryptBufferBlowfish(char data_buffer[ATC_BUF_SIZE]);
	bool parseFileEntry(ATCFileEntry *entry, const std::string& tsv_sjis, const std::string& tsv_utf8 = "");
	bool initZlib();
	bool parseHeaderEntries(stringstream *pms);

private:
	int32_t data_version_;
	char data_sub_version_;
	int32_t algorism_type_;
	char passwd_try_limit_;
	bool self_destruction_;
	string create_date_string_;
	
	int64_t total_length_;
	int64_t total_read_length_;

	CRijndael rijndael_;
	char chain_buffer_[ATC_BUF_SIZE];

	CBlowFish blowfish_;

	z_stream z_;
	int32_t z_flush_, z_status_;
	char input_buffer_[ATC_BUF_SIZE];
	char output_buffer_[ATC_LARGE_BUF_SIZE];
	string tmp_buffer_;

	vector<ATCFileEntry> entries_;
	bool broken_;
};
