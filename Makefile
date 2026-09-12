SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC := $(shell xcrun --sdk iphoneos -f clang)
ARCH := -arch arm64 -isysroot $(SDK) -miphoneos-version-min=15.0

all: IrisLite.dylib

IrisLite.dylib: cloaks.c IrisLite.m got_table.h
	$(CC) $(ARCH) -dynamiclib \
		-framework Foundation -framework UIKit -framework CoreLocation \
		-o $@ cloaks.c IrisLite.m
	strip -x $@
	codesign --force -s - $@

clean:
	rm -f IrisLite.dylib
