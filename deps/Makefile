.PHONY: all clean

DIRS=time relic emp-tool emp-ot emp-sh2pc

all: $(DIRS)
	sh ./install_packages.sh
	mkdir -p root/{lib,bin}
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
	for d in $(DIRS); do \
		make -C $$d distclean; \
	done
