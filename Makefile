SUBDIRS = src

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done
	find src/ -type f -name ".depend" | xargs rm
	find src/ -type f -name ".depend.*.o" | xargs rm
install:
	sudo bash -x ./script/install.sh
uninstall:
	sudo bash -x ./script/uninstall.sh
