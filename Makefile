CXXFLAGS = -std=c++11 -D_FILE_OFFSET_BITS=64
LDFLAGS = -lssl -lcrypto

all: boot1_extract

boot1_extract: main.o
	$(CXX) $(LDFLAGS) main.o -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	$(RM) main.o
	$(RM) boot1_extract
