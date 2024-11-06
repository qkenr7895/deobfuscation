ROOT_DIR=..
PIN_DIR=$(ROOT_DIR)/pin

TARGET_BINARY=./test_vmp
TRACE_FILE=./trace_vmp

all:
	gcc -O0 -g -o test test.c -m32

objdump:
	objdump -S test > objdump_test
	objdump -S test_vmp > objdump_test_vmp

trace:
	$(PIN_DIR)/pin -t /root/VMHunt/tracer/obj-ia32/instracelog.so -- $(TARGET_BINARY)

trace_debug:
	$(PIN_DIR)/pin -appdebug -t /root/VMHunt/tracer/obj-ia32/instracelog.so -- $(TARGET_BINARY)

clean:
	rm -f *trace* test test_vmp objdump* pin*