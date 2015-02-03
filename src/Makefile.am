bin_PROGRAMS = videosnarf

videosnarf_SOURCES = main.c stream.c videosnarf.c h264rtp.c g722_decode.c

if ARCH_X32

videosnarf_SOURCES += g726_decoder.c g729_decoder.cpp g723_decoder.cpp

endif

#videosnarf_LDFLAGS = -lpcap -L../codec-lib -lG729a -lG7231 -lG726

if ARCH_X32

videosnarf_LDADD = ../codec-lib/libG729a.a \
					  ../codec-lib/libG7231.a \
					  ../codec-lib/libG726.a
endif

#videosnarf_LDFLAGS = codec-lib/libG729a.a codec-lib/libG7231.a codec-lib/libG726.a

CLEANFILES = *.o videosnarf
