SHELL         := bash
OUTPUTBIN     := gpuacl
.DEFAULT_GOAL := all
WORKDIR       := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
SRCDIRS       := $(shell find $(WORKDIR) -type d ! -name build -print)
SRCFILES      := $(shell find $(WORKDIR) -type f -name '*.go' -print)
BUILDDIR      := $(WORKDIR)build

.PHONY: all
all: fmt quality build

.PHONY: lint
lint: $(SRCDIRS)
	revive -config $(WORKDIR)revive.toml -formatter unix $^

.PHONY: build
build:
	mkdir -p $(BUILDDIR)
	cd $(WORKDIR) && go build -o $(BUILDDIR)/$(OUTPUTBIN) .

.PHONY: fmt
fmt:
	goimports -e -w -d $(SRCFILES)
	gofmt -e -w -d $(SRCFILES)

.PHONY: _quality quality
_quality:
	test "`gofmt -l $(SRCFILES) | wc -l`" -eq 0
	test "`goimports -l $(SRCFILES) | wc -l`" -eq 0

quality: _quality lint
