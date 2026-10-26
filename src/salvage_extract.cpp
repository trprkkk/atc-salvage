// salvage_extract.cpp
//
// Best-effort extractor for AttacheCase (.atc) Ver.2.x archives that fail
// partway through normal decryption/decompression because the source file is
// damaged (e.g. copied from a failing USB drive).
//
// Behaviour:
//   - Extracts files in archive order, as the stock decoder does.
//   - When the compressed stream breaks, keeps the bytes already decoded for
//     the current file instead of discarding them ([PART]), and stops.
//   - It CANNOT go past the break: the body is one continuous deflate stream
//     that a normal decoder cannot resume after a damaged byte. For that, use
//     dump_body + resync_recover.py.
//
// Caveat: the format has no per-file checksum, so [ OK ] means "decoded
// without an error", not "verified intact".
//
// Usage:
//   ./salvage_extract <input.atc> <password> <output_dir>
//
// Built on libatc by h2so5 (https://github.com/h2so5/libatc, zlib-style
// licence; see vendor/libatc and THIRD_PARTY_NOTICES.md), modified as noted
// in those files.

#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <cstdlib>
#include <iconv.h>

#include "ATCUnlocker.h"

using namespace std;

// Convert Shift-JIS (CP932) bytes to UTF-8. Used only when the archive's
// header doesn't carry a UTF-8 name (older Ver.2.x sub-versions), so that
// extracted paths are readable/correct on a UTF-8 filesystem instead of
// being written out as raw Shift-JIS byte garbage.
static string sjisToUtf8(const string &in)
{
    iconv_t cd = iconv_open("UTF-8", "CP932");
    if (cd == (iconv_t)-1) return in; // no iconv support: fall back to raw bytes

    string out;
    out.resize(in.size() * 4 + 16);

    char *inbuf = const_cast<char*>(in.data());
    size_t inbytesleft = in.size();
    char *outbuf = &out[0];
    size_t outbytesleft = out.size();

    size_t r = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    iconv_close(cd);

    if (r == (size_t)-1)
    {
        // Couldn't convert (unexpected byte sequence) -- keep raw bytes
        // rather than losing the entry entirely.
        return in;
    }

    out.resize(out.size() - outbytesleft);
    return out;
}

static void makedirs(const string &path)
{
    string cur;
    for (size_t i = 0; i < path.size(); ++i)
    {
        char c = path[i];
        if (c == '/' || c == '\\')
        {
            if (!cur.empty())
            {
#ifdef _WIN32
                mkdir(cur.c_str());
#else
                mkdir(cur.c_str(), 0755);
#endif
            }
            cur.push_back('/');
        }
        else
        {
            cur.push_back(c);
        }
    }
    if (!cur.empty())
    {
#ifdef _WIN32
        mkdir(cur.c_str());
#else
        mkdir(cur.c_str(), 0755);
#endif
    }
}

static string sanitizeRelPath(const string &raw)
{
    // Convert backslashes to slashes and strip anything that would escape
    // the output directory (leading slashes, drive letters, "..").
    string s = raw;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] == '\\') s[i] = '/';
    }
    // strip drive letter like C:
    if (s.size() >= 2 && s[1] == ':') s = s.substr(2);
    while (!s.empty() && s[0] == '/') s = s.substr(1);

    string out;
    size_t pos = 0;
    while (pos < s.size())
    {
        size_t next = s.find('/', pos);
        string part = (next == string::npos) ? s.substr(pos) : s.substr(pos, next - pos);
        if (part != ".." && part != ".")
        {
            if (!out.empty()) out += "/";
            out += part;
        }
        if (next == string::npos) break;
        pos = next + 1;
    }
    return out;
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        cerr << "usage: " << argv[0] << " <input.atc> <password> <output_dir>" << endl;
        return 2;
    }

    string atc_path = argv[1];
    string password = argv[2];
    string out_dir = argv[3];

    char key[ATC_KEY_SIZE];
    memset(key, 0, sizeof(key));
    size_t plen = password.size();
    if (plen > ATC_KEY_SIZE) plen = ATC_KEY_SIZE; // matches original: array is just filled/truncated
    memcpy(key, password.data(), plen);

    ifstream ifs(atc_path.c_str(), ifstream::binary);
    if (!ifs)
    {
        cerr << "ERROR: cannot open " << atc_path << endl;
        return 1;
    }

    ATCUnlocker unlocker;
    ATCResult r = unlocker.open(&ifs, key);

    if (r == ATC_ERR_WRONG_KEY)
    {
        cerr << "ERROR: password rejected (or the plaintext header itself is corrupted)." << endl;
        return 1;
    }
    if (r != ATC_OK)
    {
        cerr << "ERROR: failed to open archive, code=" << r << endl;
        return 1;
    }

    size_t n = unlocker.getEntryLength();
    cerr << "Header OK. " << n << " entries. data_version=" << unlocker.data_version() << endl;

    makedirs(out_dir);

    for (size_t i = 0; i < n; ++i)
    {
        ATCFileEntry entry;
        if (unlocker.getEntry(&entry, i) != ATC_OK)
        {
            cerr << "WARN: could not read entry " << i << endl;
            continue;
        }

        string rel = entry.name_utf8.empty() ? sjisToUtf8(entry.name_sjis) : entry.name_utf8;
        string safe_rel = sanitizeRelPath(rel);
        string full_path = out_dir + "/" + safe_rel;

        bool is_dir = (entry.size < 0) || ((entry.attribute & 16) != 0);

        // ensure parent directory exists
        size_t slash = full_path.find_last_of('/');
        if (slash != string::npos)
        {
            makedirs(full_path.substr(0, slash));
        }

        if (is_dir)
        {
            makedirs(full_path);
            cerr << "[dir ] " << rel << endl;
            continue;
        }

        ofstream ofs(full_path.c_str(), ofstream::binary);
        if (!ofs)
        {
            cerr << "WARN: cannot create output file " << full_path << " (skipping)" << endl;
            // still need to consume the bytes to keep the stream aligned
        }

        size_t want = static_cast<size_t>(entry.size);
        ATCResult er = unlocker.extractFileData(&ofs, &ifs, want);

        // We don't get told exactly how many bytes were written; check the
        // resulting file size against what was expected.
        ofs.close();
        struct stat st;
        long got = 0;
        if (stat(full_path.c_str(), &st) == 0) got = static_cast<long>(st.st_size);

        if (er != ATC_OK)
        {
            cerr << "[FAIL] " << rel << " -- extraction error, code=" << er << endl;
        }
        else if (unlocker.broken())
        {
            if (got >= static_cast<long>(want))
            {
                // The current file's own bytes finished landing in
                // tmp_buffer_ before inflate() actually walked into the
                // corrupted region (which belongs to what comes next in
                // the stream). This file reached its full length.
                cerr << "[ OK ] " << rel << " (" << got << " bytes) -- "
                     << "stream breaks immediately after this file." << endl;
            }
            else
            {
                cerr << "[PART] " << rel << " -- got " << got << " / " << want
                     << " bytes, then the stream broke here (corruption boundary)." << endl;
            }
        }
        else
        {
            cerr << "[ OK ] " << rel << " (" << got << " bytes)" << endl;
        }

        if (unlocker.broken())
        {
            cerr << endl;
            cerr << "Stopping: the encrypted/compressed stream is corrupted from this point on." << endl;
            cerr << "Files listed above as [ OK ] decoded without error. The format has no" << endl;
            cerr << "per-file checksum, so this is not proof they are intact; check the last" << endl;
            cerr << "few before the break by eye. A [PART] file is recovered only up to the break." << endl;
            cerr << (n - i - 1) << " remaining entr" << ((n - i - 1) == 1 ? "y" : "ies")
                 << " in the archive could NOT be recovered by this tool." << endl;
            return 3;
        }
    }

    cerr << endl << "Done. All " << n << " entries extracted successfully." << endl;
    unlocker.close();
    return 0;
}
