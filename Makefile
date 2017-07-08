all : src/test.cpp
	g++ -g -Wall -o test src/test.cpp -lpcap
clean :
	rm test
