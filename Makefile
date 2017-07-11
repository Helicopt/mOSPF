all :
	g++ -o test src/test.cpp src/common.cpp src/ospf.cpp -lpcap
clean :
	rm test *.o
