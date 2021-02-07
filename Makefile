VERSION = 1.0.0
DIST = $(PWD)/dist
FPM_ARGS =

.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf $(DIST) *.deb

$(DIST)/mailout: server.go
	mkdir -p $(DIST)
	go build -o $(DIST)/usr/local/sbin/mailout

.PHONY: deb
deb: $(DIST)/mailout
	fpm -n mailout -s dir -t deb --chdir=$(DIST) --version=$(VERSION) $(FPM_ARGS)
