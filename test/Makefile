all: lib test

test:
	g++ -g -I../include -O0 test.cpp -o test.elf -std=c++0x -ldl -L. -lhook

lib:
	gcc -g -I../include -fPIC -shared -O0 -o libhook.so ../src/hook.c ../src/ltrace-elf.c -ldl -lelf

clean:
	rm -rf *.elf *.so
