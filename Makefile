# atc-salvage -- build the C++ helper tools and run the test-suite.
#
#   make          build bin/salvage_extract and bin/dump_body
#   make test     build everything and run tests/run_tests.py
#   make clean
#
# Needs: a C++11 compiler, zlib headers (e.g. zlib1g-dev), python3 (stdlib only).
# Tested on Linux (glibc).

CXX      ?= g++
CXXFLAGS ?= -O2
CXXFLAGS += -std=gnu++11 -DNODEBUG -Ivendor/libatc
LDLIBS   += -lz

V = vendor/libatc
B = build

UNLOCK_OBJS = $(B)/ATCUnlocker.o $(B)/ATCUnlocker_impl.o $(B)/Rijndael.o $(B)/blowfish.o
LOCK_OBJS   = $(B)/ATCLocker.o $(B)/ATCLocker_impl.o $(B)/isaac.o

all: bin/salvage_extract bin/dump_body

bin/salvage_extract: $(UNLOCK_OBJS) $(B)/salvage_extract.o | bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

bin/dump_body: $(UNLOCK_OBJS) $(B)/dump_body.o | bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

# Test-archive generator (uses the unmodified upstream encryptor).
bin/make_test_archive: $(UNLOCK_OBJS) $(LOCK_OBJS) $(B)/make_test_archive.o | bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(B)/%.o: $(V)/%.cpp | $(B)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# isaac.c is compiled as C++ on purpose (its header has no extern "C" guard).
$(B)/isaac.o: $(V)/isaac.c | $(B)
	$(CXX) $(CXXFLAGS) -x c++ -c -o $@ $<

$(B)/%.o: src/%.cpp | $(B)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(B)/make_test_archive.o: tests/make_test_archive.cpp | $(B)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

bin $(B):
	mkdir -p $@

test: all bin/make_test_archive
	python3 tests/run_tests.py

clean:
	rm -rf $(B) bin

.PHONY: all test clean
