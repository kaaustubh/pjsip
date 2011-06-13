# build/os-auto.mak.  Generated from os-auto.mak.in by configure.

export OS_CFLAGS   := $(CC_DEF)PJ_AUTOCONF=1 -O2 -Wno-unused-label  -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk

export OS_CXXFLAGS := $(CC_DEF)PJ_AUTOCONF=1 -O2 -Wno-unused-label  -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk 

export OS_LDFLAGS  := -O2  -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk -framework AudioToolbox -framework Foundation -lpthread  -framework CoreAudio -framework CoreFoundation -framework AudioToolbox

export OS_SOURCES  := 


