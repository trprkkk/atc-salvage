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

#include "ATCLocker_impl.h"

/*
 * NOTE (atc-salvage): This file is an ALTERED version of the file of the same
 * name from libatc by h2so5 (https://github.com/h2so5/libatc). The only
 * change is in fillrand(): upstream wrote an 8-byte `unsigned long` into a
 * 4-byte buffer, which overflows the stack on 64-bit platforms (make test
 * aborts with "stack smashing detected" on modern 64-bit Linux). The write
 * is now a 4-byte uint32_t. The original copyright and licence notice above
 * is unchanged.
 */


ATCLocker_impl::ATCLocker_impl() :

passwd_try_limit_(ATC_DEFAULT_PASSWORD_TRY_LIMIT),
self_destruction_(false),
compression_level_(Z_DEFAULT_COMPRESSION),

total_length_(0),
total_write_length_(0),

finished_(false)

{
	time(&create_time_);
}


ATCLocker_impl::~ATCLocker_impl()
{
	close();
}

ATCResult ATCLocker_impl::open(ostream *dst, const char key[ATC_KEY_SIZE])
{
	const char zero[ATC_KEY_SIZE] = {0};
	if (memcmp(zero, key, ATC_KEY_SIZE) == 0)
	{
		return ATC_ERR_NULL_KEY;
	}

	string header;
	generatePlainHeader(&header);

	dst->write(header.data(), header.size());

	rijndael_.MakeKey(key, CRijndael::sm_chain0, ATC_KEY_SIZE, ATC_BUF_SIZE);

	if (dst->good())
	{
		return ATC_OK;
	} else {
		return ATC_ERR_OSTREAM_FAILURE;
	}
}

ATCResult ATCLocker_impl::close()
{
	return ATCLocker_impl::finish();
}

ATCResult ATCLocker_impl::addFileEntry(const ATCFileEntry& entry)
{
	if (entry.name_sjis.size() > 0 && entry.name_utf8.size())
	{
		entries_.push_back(entry);
		return ATC_OK;
	} else {
		return ATC_ERR_INVARID_FILE_ENTRY;
	}
}

namespace {
	template <class T>
	string convertToString(T src)
	{
		stringstream converter;
		converter << src;
		return converter.str();
	}

	void unix_to_ttime(time_t unix, int32_t *dt, int32_t *tm)
	{
		// 西洋紀元からUNIX紀元までの日数
		static const int32_t days_between_ad_epoch_and_unix_epoch = 719162;
		struct tm timeinfo;
		
		*dt = days_between_ad_epoch_and_unix_epoch + static_cast<int32_t>(unix) / (60 * 60 * 24) + 1;

#ifdef WIN32
			gmtime_s(&timeinfo, &unix);
#else
			timeinfo = *gmtime(&unix);
#endif

		*tm = timeinfo.tm_sec * 1000 + 
			timeinfo.tm_min   * 1000 * 60 + 
			timeinfo.tm_hour  * 1000 * 60 * 60;
	}
}

ATCResult ATCLocker_impl::writeEncryptedHeader(ostream *dst)
{
	stringstream whole_header;
	generateEncryptedHeader(&whole_header);

	//暗号化部分のヘッダデータサイズを計算
	const int32_t block_length = (whole_header.str().size() + ATC_BUF_SIZE - 1) / ATC_BUF_SIZE;
	const int32_t encrypt_header_size = block_length * ATC_BUF_SIZE;

	dst->write(reinterpret_cast<const char*>(&encrypt_header_size), sizeof(int32_t));

	//初期化ベクトル（IV）を生成
	fillrand(chain_buffer_, ATC_BUF_SIZE);
	dst->write(chain_buffer_, ATC_BUF_SIZE);

	char buffer[ATC_BUF_SIZE] = {0};

	while (whole_header.read(buffer, ATC_BUF_SIZE).gcount() != 0)
	{
		encryptBuffer(buffer, chain_buffer_);

		dst->write(buffer, ATC_BUF_SIZE);
		for (int i = 0; i < ATC_BUF_SIZE; i++)
		{
			buffer[i] = 0;
		}
	}

	//初期化ベクトル（IV）を生成
	fillrand(chain_buffer_, ATC_BUF_SIZE);
	dst->write(chain_buffer_, ATC_BUF_SIZE);

	if (!initZlib())
	{
        return ATC_ERR_ZLIB_ERROR;
    }

	return ATC_OK;
}

ATCResult ATCLocker_impl::writeFileData(ostream *dst, istream *src, size_t length)
{
	int rest_length = length;
    while (1)
	{
        if (z_.avail_in == 0)
		{
			size_t read_length = (rest_length < ATC_BUF_SIZE) ? rest_length : ATC_BUF_SIZE;

            z_.next_in = reinterpret_cast<Bytef*>(input_buffer_);
			z_.avail_in = static_cast<uInt>(src->read(input_buffer_, read_length).gcount());
			
			rest_length -= z_.avail_in;
			total_write_length_ += z_.avail_in;

			if (total_write_length_ >= total_length_) 
			{
				z_flush_ = Z_FINISH;
			}
        }

		// TODO: コメントアウトするとなぜか正常に出力しない
		// if(z_.avail_in == 0) break;

        z_status_ = deflate(&z_, z_flush_);

        if (z_status_ == Z_STREAM_END)
		{
			break;
		}

        if (z_status_ != Z_OK)
		{
			if (z_status_ == Z_BUF_ERROR)
			{
				return ATC_OK;
			} else {
				return ATC_ERR_ZLIB_ERROR;
			}
        }

        if (z_.avail_out == 0)
		{
			encryptBuffer(output_buffer_, chain_buffer_);
			dst->write(output_buffer_, ATC_BUF_SIZE);

			z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
			z_.avail_out = ATC_BUF_SIZE;
        }
    }

    if (z_status_ == Z_STREAM_END)
	{
		int32_t count;
		if ((count = ATC_BUF_SIZE - z_.avail_out) != 0)
		{
			char padding_num = (char)z_.avail_out;
			for(int i = count; i < ATC_BUF_SIZE; i++)
			{
				output_buffer_[i] = padding_num;
			}
			encryptBuffer(output_buffer_, chain_buffer_);
			dst->write(output_buffer_, ATC_BUF_SIZE);
		}

		return finish();
	}

	return ATC_OK;
}

bool ATCLocker_impl::initZlib()
{
    z_.zalloc = Z_NULL;
    z_.zfree  = Z_NULL;
    z_.opaque = Z_NULL;

    if (deflateInit(&z_, compression_level_) != Z_OK)
	{
        return false;
    }

    z_.avail_in = 0;
    z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
    z_.avail_out = ATC_BUF_SIZE;
    z_flush_ = Z_NO_FLUSH;

	return true;
}

void ATCLocker_impl::generatePlainHeader(string *dst)
{
	static const char null[] = {0, 0, 0, 0};
	static const char data_sub_version = ATC_DATA_SUB_VERSION;
	static const char token_string[] = "_AttacheCaseData";
	static const int32_t data_file_version = ATC_DATA_FILE_VERSION;
	static const int32_t algorism_type = ATC_ALGORISM_TYPE_RIJNDAEL;
	const char self_destruction = static_cast<char>(self_destruction_);

	//データサブバージョン
	*dst += string(&data_sub_version, sizeof(char));

	//予約データ(reserved)
	*dst += string(null, sizeof(char));

	//ミスタイプ回数
	*dst += string(&passwd_try_limit_, sizeof(char));

	//自己破壊
	*dst += string(&self_destruction, sizeof(char));

	//トークン
	*dst += string(token_string, 16);

	//データファイルバージョン
	*dst += string(reinterpret_cast<const char*>(&data_file_version), sizeof(int32_t));

	//アルゴリズムタイプ
	*dst += string(reinterpret_cast<const char*>(&algorism_type), sizeof(int32_t));
}

void ATCLocker_impl::generateEncryptedHeader(stringstream *dst)
{
	string date_string;
	getCurrentDateString(&date_string);

	static const char separator[] = {(char)0xef, (char)0xbb, (char)0xbf};
	string sjis_header = "Passcode:AttacheCase\n\r\nLastDateTime:" + date_string + "\n\r\n";
	string utf8_header = "Passcode:AttacheCase\n\r\nLastDateTime:" + date_string + "\n\r\n";

	int32_t count = 0;
	for (vector<ATCFileEntry>::iterator it = entries_.begin(); it != entries_.end(); ++it)
	{
		sjis_header += "Fn_" + convertToString(count) + ":";
		utf8_header += "U_"  + convertToString(count) + ":";

		sjis_header += it->name_sjis + "\t";
		utf8_header += it->name_utf8 + "\t";

		string common;
		common.reserve(128);

		if (it->size < 0) {
			common += "*\t";
		} else {
			common += convertToString(it->size) + "\t";
			total_length_ += it->size;
		}

		common += convertToString(it->attribute)   + "\t";

		int32_t change_dt, change_tm;
		int32_t create_dt, create_tm;

		// UNIX時間 から TTimeStampへ変換
		unix_to_ttime(it->change_unix_time, &change_dt, &change_tm);
		unix_to_ttime(it->create_unix_time, &create_dt, &create_tm);

		common += convertToString(change_dt) + "\t";
		common += convertToString(change_tm) + "\t";
		common += convertToString(create_dt) + "\t";
		common += convertToString(create_tm);
		common += "\r\n";

		sjis_header += common;
		utf8_header += common;

		count++;
	}

	dst->str(sjis_header + string(separator, sizeof(separator)) + utf8_header);
}

ATCResult ATCLocker_impl::finish()
{
	if (!finished_)
	{
		finished_ = true;
		if (deflateEnd(&z_) != Z_OK)
		{
			return ATC_ERR_ZLIB_ERROR;
		}
	}

	return ATC_OK;
}

void ATCLocker_impl::fillrand(char *buf, const int len)
{
	uint32_t count = 4;
	uint8_t r[4] = {0};

	// ISAAC ( Cryptographic Random Number Generator )
	randctx ctx;

	// init
	randinit(&ctx, 1);

	for(int i = 0; i < len; ++i)
	{
		if(count == 4)
		{
			*(uint32_t*)r = rand(&ctx);
			count = 0;
		}
		buf[i] = r[count++];
	}
}

void ATCLocker_impl::getCurrentDateString(string *dst)
{
	struct tm timeinfo;
	char buffer [80];

#ifdef WIN32
	localtime_s(&timeinfo, &create_time_);
#else
	timeinfo = *localtime(&create_time_);
#endif

	strftime(buffer, 80, "%Y/%m/%d %H:%M:%S", &timeinfo);

	*dst = string(buffer);
}


void ATCLocker_impl::encryptBuffer(char data_buffer[ATC_BUF_SIZE], char iv_buffer[ATC_BUF_SIZE])
{
	// xor
	for (int i = 0; i < ATC_BUF_SIZE; i++ )
	{
		data_buffer[i] ^= iv_buffer[i];
	}

	// rijndael
	rijndael_.EncryptBlock(data_buffer, data_buffer);

	memcpy(iv_buffer, data_buffer, ATC_BUF_SIZE);
}

char ATCLocker_impl::passwd_try_limit() const
{
	return passwd_try_limit_;
}

bool ATCLocker_impl::self_destruction() const
{
	return self_destruction_;
}

int32_t ATCLocker_impl::compression_level() const
{
	return compression_level_;
}

time_t ATCLocker_impl::create_time() const
{
	return create_time_;
}

void ATCLocker_impl::set_passwd_try_limit(const char passwd_try_limit)
{
	passwd_try_limit_ = passwd_try_limit;
}

void ATCLocker_impl::set_self_destruction(const bool self_destruction)
{
	self_destruction_ = self_destruction;
}

void ATCLocker_impl::set_compression_level(const int32_t compression_level)
{
	compression_level_ = compression_level;
}

void ATCLocker_impl::set_create_time(const time_t create_time)
{
	create_time_ = create_time;
}

#ifdef USE_CLI

namespace {

	void writeToStream(Stream ^dst, const char *src, size_t length)
	{
		array<System::Byte, 1>^ buffer = gcnew array<System::Byte, 1>(length);
		pin_ptr<System::Byte> buffer_native = &buffer[0];

		memcpy(buffer_native, src, length);

		dst->Write(buffer, 0, length);
		buffer_native = nullptr;
	}

};

ATCResult ATCLocker_impl::open(Stream ^dst, array<System::Byte, 1> ^key)
{
	array<System::Byte, 1>^ key_buffer = gcnew array<System::Byte, 1>(ATC_KEY_SIZE);
	key->CopyTo(key_buffer, 0);

	string header;
	generatePlainHeader(&header);

	writeToStream(dst, header.data(), header.size());

	// キーをセット
	{
		pin_ptr<System::Byte> buffer_native = &key_buffer[0];
		rijndael_.MakeKey(reinterpret_cast<const char*>(buffer_native),
			CRijndael::sm_chain0, ATC_KEY_SIZE, ATC_BUF_SIZE);

		buffer_native = nullptr;
	}

	if (dst->CanWrite)
	{
		return ATC_OK;
	} else {
		return ATC_ERR_OSTREAM_FAILURE;
	}
}

ATCResult ATCLocker_impl::writeEncryptedHeader(Stream ^dst)
{
	stringstream whole_header;
	generateEncryptedHeader(&whole_header);

	//暗号化部分のヘッダデータサイズを計算
	const int32_t block_length = (whole_header.str().size() + ATC_BUF_SIZE - 1) / ATC_BUF_SIZE;
	const int32_t encrypt_header_size = block_length * ATC_BUF_SIZE;

	writeToStream(dst, reinterpret_cast<const char*>(&encrypt_header_size), sizeof(encrypt_header_size));

	//初期化ベクトル（IV）を生成
	fillrand(chain_buffer_, ATC_BUF_SIZE);
	writeToStream(dst, chain_buffer_, ATC_BUF_SIZE);

	{
		char buffer[ATC_BUF_SIZE];

		while (whole_header.read(reinterpret_cast<char*>(buffer), ATC_BUF_SIZE).gcount() != 0)
		{
			encryptBuffer(reinterpret_cast<char*>(buffer), chain_buffer_);
			writeToStream(dst, buffer, ATC_BUF_SIZE);

			for (int i = 0; i < ATC_BUF_SIZE; i++)
			{
				buffer[i] = 0;
			}
		}
	}

	//初期化ベクトル（IV）を生成
	fillrand(chain_buffer_, ATC_BUF_SIZE);
	writeToStream(dst, chain_buffer_, ATC_BUF_SIZE);

	if (!initZlib())
	{
        return ATC_ERR_ZLIB_ERROR;
    }

	return ATC_OK;
}

ATCResult ATCLocker_impl::writeFileData(Stream ^dst, Stream ^src, size_t length)
{
	int rest_length = length;
    while (1)
	{
        if (z_.avail_in == 0)
		{
			size_t read_length = (rest_length < ATC_BUF_SIZE) ? rest_length : ATC_BUF_SIZE;

            z_.next_in = reinterpret_cast<Bytef*>(input_buffer_);

			array<System::Byte, 1>^ buffer = gcnew array<System::Byte, 1>(ATC_BUF_SIZE);
			z_.avail_in = src->Read(buffer, 0, buffer->Length);

			{
				pin_ptr<System::Byte> buffer_native = &buffer[0];
				memcpy(input_buffer_, buffer_native, ATC_BUF_SIZE);

				buffer_native = nullptr;
			}
			
			rest_length -= z_.avail_in;
			total_write_length_ += z_.avail_in;

			if (total_write_length_ >= total_length_) 
			{
				z_flush_ = Z_FINISH;
			}
        }

		// TODO: コメントアウトするとなぜか正常に出力しない
		// if(z_.avail_in == 0) break;

        z_status_ = deflate(&z_, z_flush_);

        if (z_status_ == Z_STREAM_END)
		{
			break;
		}

        if (z_status_ != Z_OK)
		{
			if (z_status_ == Z_BUF_ERROR)
			{
				return ATC_OK;
			} else {
				return ATC_ERR_ZLIB_ERROR;
			}
        }

        if (z_.avail_out == 0)
		{
			encryptBuffer(output_buffer_, chain_buffer_);
			writeToStream(dst, output_buffer_, ATC_BUF_SIZE);

			z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
			z_.avail_out = ATC_BUF_SIZE;
        }
    }

    if (z_status_ == Z_STREAM_END)
	{
		int32_t count;
		if ((count = ATC_BUF_SIZE - z_.avail_out) != 0)
		{
			char padding_num = (char)z_.avail_out;
			for(int i = count; i < ATC_BUF_SIZE; i++)
			{
				output_buffer_[i] = padding_num;
			}

			encryptBuffer(output_buffer_, chain_buffer_);
			writeToStream(dst, output_buffer_, ATC_BUF_SIZE);

		}

		return finish();
	}

	return ATC_OK;
}

#endif