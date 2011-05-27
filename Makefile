CC= gcc
CXX= g++

CFLAGS= -g -O2 -D__AES__ -mssse3 -Wall -Wextra
#CFLAGS= -g -O2 -Wall -Wextra -mno-sse2
LDFLAGS= -g

all: test_random bench

test_random: test_random.o crandom.o chacha.o aes.o
	$(CXX) $(LDFLAGS) -o $@ $^

bench: bench.o chacha.o aes.o
	$(CXX) $(LDFLAGS) -o $@ $^

chacha.o: chacha.cpp chacha.hpp Makefile
	$(CXX) $(CFLAGS) -c -o $@ $<

aes.o: aes.cpp aes.hpp Makefile
	$(CXX) $(CFLAGS) -c -o $@ $<

crandom.o: crandom.cpp crandom.hpp chacha.hpp Makefile
	$(CXX) $(CFLAGS) -c -o $@ $<

test_random.o: test_random.cpp crandom.hpp chacha.hpp aes.hpp Makefile
	$(CXX) $(CFLAGS) -c -o $@ $<

bench.o: bench.cpp chacha.hpp aes.hpp Makefile
	$(CXX) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o test_random bench