VERSION = 1.0.0
DIST = $(PWD)/dist

.PHONY: clean
clean:
	rm -rf $(DIST) *.deb

$(DIST)/mailout: server.go
	mkdir -p $(DIST)
	go build -o $(DIST)/usr/local/sbin/mailout

.PHONY: deb
deb: $(DIST)/mailout
	fpm -n mailout -s dir -t deb --chdir=$(DIST) --version=$(VERSION)
