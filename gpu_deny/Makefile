.DEFAULT_GOAL := all

BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin
SRC_DIR := src
LIBBPF_DIR ?= ../libbpf/src/

LLC ?= llc
CLANG ?= clang
CC ?= gcc

DEBUG ?= 0
BPF_FLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -O2 -g -target bpf
CFLAGS ?= -Wall -I$(LIBBPF_DIR)/build/usr/include/ -g
LDFLAGS ?= -L$(LIBBPF_DIR)
LIBS = -l:libbpf.a -lelf -lz

ifeq ($(DEBUG), 1)
	BPF_FLAGS += -DDEBUG
	CFLAGS += -DDEBUG
endif

.PHONY: bpf clean all libbpflib libbpfheaders $(CLANG) $(LLC)

libbpfheaders:
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) \
		mkdir -p build; \
		$(MAKE) install_headers DESTDIR=build OBJDIR=.; \
	fi

libbpflib: libbpfheaders
	cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \

$(BUILD_DIR)/gpu_selector: $(SRC_DIR)/gpu_selector.c libbpflib | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(BUILD_DIR)/gpu_deny.o: $(SRC_DIR)/gpu_deny.c libbpfheaders | $(BUILD_DIR)
	$(CLANG) $(BPF_FLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

all: llvm-check bpf userland

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

bpf: $(BUILD_DIR)/gpu_deny.o

userland: $(BUILD_DIR)/gpu_selector

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -rf $(BUILD_DIR)
