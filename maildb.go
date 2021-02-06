package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func updateMailStatus(domain string, uuid string, status int) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/db/domain/%s/update/%s", config.PortMaildb, domain, uuid)
	body := fmt.Sprintf("{\"status\":%d}", status)
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		return err
	}

	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
}
