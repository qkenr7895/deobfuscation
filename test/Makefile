ROOT_DIR=..
PIN_DIR=$(ROOT_DIR)/pin
TRACER_DIR=$(ROOT_DIR)/deobfuscator/tracer
VMP_CONSOLE=$(ROOT_DIR)/vmprotect/vmprotect_con

TRACE_FILES=trace vm_enter vm_exit vm_enter_call vm_exit_ret

CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -I$(SRC_DIR)/VMProtect_SDK/include
LDFLAGS = -L$(SRC_DIR)/VMProtect_SDK/lib -lVMProtectSDK64

SRC_DIR = ./source
BUILD_DIR = ./test

ALL_SOURCES = $(wildcard $(SRC_DIR)/*.c)
ALL_BINS = $(patsubst $(SRC_DIR)/%.c,%,$(ALL_SOURCES))

ifdef FILES
	BINS = $(FILES)
else
	BINS = $(ALL_BINS)
endif

binary: $(BINS)

$(BINS):
	@mkdir -p $(BUILD_DIR)/$@
	$(CC) $(CFLAGS) $(SRC_DIR)/$@.c -o $(BUILD_DIR)/$@/$@ $(LDFLAGS)
	@if [ -f $(SRC_DIR)/$@.vmp ]; then \
		echo "[VMProtect] Applying protection to $@"; \
		$(VMP_CONSOLE) $(BUILD_DIR)/$@/$@ $(BUILD_DIR)/$@/$@_vmp -pf $(SRC_DIR)/$@.vmp ; \
	else \
		echo "[VMProtect] No .vmp config found for $@, skipping protection."; \
	fi

trace:
	@$(foreach bin,$(BINS), \
		echo "Tracing $(bin)..."; \
		$(PIN_DIR)/pin -t $(TRACER_DIR)/obj-intel64/instracelog.so -- $(BUILD_DIR)/$(bin)/$(bin)_vmp; \
		$(foreach file,$(TRACE_FILES),mv $(file) $(BUILD_DIR)/$(bin)/;) \
	)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: binary clean $(BINS)
