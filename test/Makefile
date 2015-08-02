all: lib test

test:
	g++ -g -I../include -fPIC -shared -O0 -o libtest2.so test2.cpp  -std=c++0x
	g++ -g -DLIB_NAME=\"libtest2.so\" -I../include -O0 test.cpp -o test.elf -std=c++0x -ldl -L. -lhook -ltest2

lib:
	#gcc -g -I../include -fPIC -shared -O0 -o libhook.so ../src/hook.c ../src/ltrace-elf.c -ldl -lelf
	gcc -g -I../include -fPIC -shared -O0 -o libhook.so ../src/hook.c  -ldl -lelf

clean:
	rm -rf *.elf *.so
