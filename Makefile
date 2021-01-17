VERSION = 1.0.0
DIST = $(PWD)/dist

.PHONY: clean
clean:
	rm -rf $(DIST) *.deb

$(DIST)/smtp-send: server.go
	mkdir -p $(DIST)
	go build -o $(DIST)/usr/local/sbin/smtp-send

.PHONY: deb
deb: $(DIST)/smtp-send
	fpm -n smtp-send -s dir -t deb --chdir=$(DIST) --version=$(VERSION)
