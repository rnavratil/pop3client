CXX=g++
CXXFLAGS=-c -pedantic -std=c++11
INCLUDES=-I/usr/local/opt/openssl/include 
LIBS= -lssl -lcrypto -L/usr/local/opt/openssl/lib
SRC = $(wildcard *.cpp)
OBJ = $(patsubst %.cpp, %.o, $(SRC))

all: popcl 

popcl: popcl.o
	$(CXX)  $(INLUDES) -o popcl popcl.o $(LIBS)

popcl.o:popcl.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c popcl.cpp
clean:
	rm -f *.o popcl 
