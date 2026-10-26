// make_test_archive.cpp -- builds a synthetic multi-file AttacheCase archive
// for the test-suite. Not part of the salvage tools themselves.
//
// Usage: make_test_archive <sample.jpg> <out.atc> <num_files>
//
// Entry i is a copy of the sample JPEG with bytes altered from offset 1000
// on (the JPEG signature stays valid), so every file has distinct content.
// Names use Windows-style backslash separators on purpose, as archives made
// on Windows do, to exercise path normalisation. tests/run_tests.py rebuilds
// the same content independently to compare against.
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "ATCLocker.h"

using namespace std;

static string read_file(const char *path)
{
    ifstream f(path, ifstream::binary);
    stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "usage: %s <sample.jpg> <out.atc> <num_files>\n", argv[0]);
        return 2;
    }
    const string jpg = read_file(argv[1]);
    const int n = atoi(argv[3]);
    if (jpg.empty() || n <= 0)
    {
        fprintf(stderr, "bad input\n");
        return 2;
    }

    char key[ATC_KEY_SIZE] = "testpass";
    const time_t t = time(NULL);

    vector<string> names, datas;
    for (int i = 0; i < n; i++)
    {
        char name[64];
        snprintf(name, sizeof(name), "Folder%02d\\Sub\\photo_%04d.jpg", i % 4, i);
        names.push_back(name);

        const int m = i % 50;
        string d = jpg;
        for (size_t k = 1000; k < d.size(); k += (37 + m))
            d[k] ^= static_cast<char>(0x11 + m);
        datas.push_back(d);
    }

    ofstream ofs(argv[2], ofstream::binary);
    ATCLocker locker;
    locker.open(&ofs, key);
    for (int i = 0; i < n; i++)
    {
        ATCFileEntry e;
        e.attribute = 0;
        e.size = datas[i].size();
        e.name_sjis = names[i];
        e.name_utf8 = names[i];
        e.change_unix_time = t;
        e.create_unix_time = t;
        locker.addFileEntry(e);
    }
    locker.writeEncryptedHeader(&ofs);
    for (int i = 0; i < n; i++)
    {
        stringstream s(datas[i]);
        locker.writeFileData(&ofs, &s, datas[i].size());
    }
    locker.close();
    ofs.close();
    return 0;
}
