all :
	g++ -o test src/test.cpp src/common.cpp src/ospf.cpp -lpcap -pthread
clean :
	rm test *.o
