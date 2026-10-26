// dump_body.cpp
//
// Decrypts the ENTIRE body of a (possibly damaged) AttacheCase Ver.2.x
// .atc file into one flat binary file, completely independent of zlib.
// Because Rijndael-CBC decryption self-synchronizes after two 32-byte
// blocks, this recovers the correct byte-for-byte compressed stream
// everywhere except the handful of blocks that are genuinely damaged on
// disk -- even in places where the AttacheCase software (or the earlier
// salvage_extract tool) would already have given up because zlib itself
// can no longer make sense of the sequence.
//
// Also writes a JSON manifest of every entry (name/size/is_dir, in
// archive order) so a downstream tool can work out file boundaries
// without needing the password or any crypto code.
//
// Usage:
//   ./dump_body <input.atc> <password> <output_body.bin> <output_manifest.json>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iconv.h>

#include "ATCUnlocker.h"

using namespace std;

static string sjisToUtf8(const string &in)
{
    iconv_t cd = iconv_open("UTF-8", "CP932");
    if (cd == (iconv_t)-1) return in;

    string out;
    out.resize(in.size() * 4 + 16);

    char *inbuf = const_cast<char*>(in.data());
    size_t inbytesleft = in.size();
    char *outbuf = &out[0];
    size_t outbytesleft = out.size();

    size_t r = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    iconv_close(cd);

    if (r == (size_t)-1) return in;

    out.resize(out.size() - outbytesleft);
    return out;
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

static string jsonEscape(const string &s)
{
    string out;
    for (unsigned char c : s)
    {
        switch (c)
        {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20)
                {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                }
                else
                {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        cerr << "usage: " << argv[0] << " <input.atc> <password> <output_body.bin> <output_manifest.json>" << endl;
        return 2;
    }

    string atc_path = argv[1];
    string password = argv[2];
    string body_out = argv[3];
    string manifest_out = argv[4];

    char key[ATC_KEY_SIZE];
    memset(key, 0, sizeof(key));
    size_t plen = password.size();
    if (plen > ATC_KEY_SIZE) plen = ATC_KEY_SIZE;
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
        cerr << "ERROR: password rejected (or plaintext header corrupted)." << endl;
        return 1;
    }
    if (r != ATC_OK)
    {
        cerr << "ERROR: failed to open archive, code=" << r << endl;
        return 1;
    }

    size_t n = unlocker.getEntryLength();
    cerr << "Header OK. " << n << " entries. Writing manifest..." << endl;

    {
        ofstream mf(manifest_out.c_str());
        mf << "[\n";
        for (size_t i = 0; i < n; ++i)
        {
            ATCFileEntry entry;
            unlocker.getEntry(&entry, i);
            string rel = entry.name_utf8.empty() ? sjisToUtf8(entry.name_sjis) : entry.name_utf8;
            rel = sanitizeRelPath(rel);
            bool is_dir = (entry.size < 0) || ((entry.attribute & 16) != 0);
            mf << "  {\"index\": " << i
               << ", \"name\": \"" << jsonEscape(rel) << "\""
               << ", \"size\": " << (is_dir ? 0 : entry.size)
               << ", \"is_dir\": " << (is_dir ? "true" : "false")
               << "}" << (i + 1 < n ? "," : "") << "\n";
        }
        mf << "]\n";
    }

    cerr << "Decrypting full body (this reads the whole file once)..." << endl;
    ofstream body(body_out.c_str(), ofstream::binary);
    if (!body)
    {
        cerr << "ERROR: cannot create " << body_out << endl;
        return 1;
    }
    unlocker.dumpRawDecryptedBody(&body, &ifs);
    body.close();

    cerr << "Done. Wrote " << manifest_out << " and " << body_out << endl;
    return 0;
}
