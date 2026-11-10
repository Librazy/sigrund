all: sigrund_daemon.pp sigrund_workload.pp sigrund_requester.pp

# Optional; requires the installed container-selinux policy types.
podman: sigrund_podman.pp
sigrund_podman.pp: sigrund_podman.fc
%.pp: %.te
	$(MAKE) -f /usr/share/selinux/devel/Makefile $@
.PHONY: all podman
