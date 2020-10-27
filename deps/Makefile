.PHONY: all clean

DIRS=time emp-tool emp-ot emp-sh2pc emp-ag2pc update-state

all: $(DIRS)
	./install_packages.sh
	mkdir -p root/lib
	mkdir -p root/bin
	for d in $(DIRS); do \
		make -C $$d; \
	done

clean: $(DIRS)
	rm -rf root
	for d in $(DIRS); do \
		make -C $$d clean; \
	done

distclean: $(DIRS)
	rm -rf root
	rm -f .installed
	for d in $(DIRS); do \
		make -C $$d distclean; \
	done
