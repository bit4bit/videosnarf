BCG729_SRC=bcg729
BCG729_CMAKELISTS=$(BCG729_SRC)/src/CMakeLists.txt

all: bcg729

clone_bcg729:
	if [ ! -d bcg729 ]; then \
                git clone git://git.linphone.org/bcg729.git; \
		if ! grep STATIC $(BCG729_CMAKELISTS); then\
			echo  'add_library(bcg729static STATIC $${BCG729_SOURCE_FILES})' >> ${BCG729_CMAKELISTS};\
		 fi \
        fi

bcg729: clone_bcg729
	cd ${BCG729_SRC} && cmake . && make && cd ..

clean:
	cd ${BCG729_SRC} && make clean; cd ..

distclean:
	rm -fR ${BCG729_SRC}
