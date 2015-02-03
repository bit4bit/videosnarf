bin_PROGRAMS = videosnarf

videosnarf_SOURCES = main.c stream.c videosnarf.c h264rtp.c g722_decode.c g729_decoder.c
videosnarf_LDFLAGS = -I../libbcg729/bcg729/include  -L../libbcg729/bcg729/src/ -lbcg729

if ARCH_X32

videosnarf_SOURCES += g726_decoder.c g723_decoder.cpp

endif

if ARCH_X32

videosnarf_LDADD = ../codec-lib/libG7231.a \
					  ../codec-lib/libG726.a
endif


CLEANFILES = *.o videosnarf
