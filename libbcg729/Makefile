all: bcg729

clone_bcg729:
	if [ ! -d bcg729 ]; then \
                git clone git://git.linphone.org/bcg729.git; \
        fi

bcg729: clone_bcg729
	cd bcg729 && cmake . && make && cd ..

clean:
	cd bcg729 && make clean; cd ..

distclean:
	rm -fR bcg729
