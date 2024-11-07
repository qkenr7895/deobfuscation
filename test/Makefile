ROOT_DIR=..
PIN_DIR=$(ROOT_DIR)/pin
TRACER_DIR=$(ROOT_DIR)/deobfuscator/tracer

TARGET_BINARY=./test_vmp
TRACE_FILE=./trace_vmp

all:
	gcc -O0 -g -o test_native test.c

objdump:
	objdump -S test_native > objdump_test_native
	objdump -S test_vmp > objdump_test_vmp

trace:
	$(PIN_DIR)/pin -t $(TRACER_DIR)/obj-intel64/instracelog.so -- $(TARGET_BINARY)
	mv instrace.txt $(TRACE_FILE)

trace_debug:
	$(PIN_DIR)/pin -appdebug -t $(TRACER_DIR)/obj-intel64/instracelog.so -- $(TARGET_BINARY)

clean:
	rm -f trace* test_* objdump* pin*