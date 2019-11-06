.PHONY: all clean

VERSION=toolkit-0.5.0
TMP=$(shell mktemp -d tmp-XXXX)

all: package relic-$(VERSION)/.built

# TODO: add -DOPSYS=$(THE_OS) flag

relic-$(VERSION)/.built: relic-${VERSION}
	cd $(TMP); \
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$(ZK_DEPS_INSTALL) -DALIGN=16 -DARCH=X64 -DARITH=curve2251-sse -DCHECK=off -DFB_POLYN=251 -DFB_METHD="INTEG;INTEG;QUICK;QUICK;QUICK;QUICK;LOWER;SLIDE;QUICK" -DFB_PRECO=on -DFB_SQRTF=off -DEB_METHD="PROJC;LODAH;COMBD;INTER" -DEC_METHD="CHAR2" -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -march=native -msse4.2 -mpclmul" -DTIMER=CYCLE -DWITH="MD;DV;BN;FB;EB;EC" -DWSIZE=64 ../$<; \
	make && \
	make install && \
	touch ../$@ && \
	../fix_rpath_osx.sh librelic

relic-$(VERSION): relic-$(VERSION).tar.gz
	tar xf $^

package:
	./download_relic.sh relic-$(VERSION)

clean:
	rm -rf relic-$(VERSION) tmp*

distclean:
	rm -rf relic-$(VERSION)* tmp* 
