all: sigrund_daemon.pp sigrund_workload.pp sigrund_requester.pp
%.pp: %.te
	$(MAKE) -f /usr/share/selinux/devel/Makefile $@
.PHONY: all
