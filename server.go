package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/mail"
	netsmtp "net/smtp"
	"os"
	"strings"
	"time"

	smtpclient "github.com/mailway-app/go-smtp/client"
	smtpserver "github.com/mailway-app/go-smtp/server"
	dkim "github.com/toorop/go-dkim"
)

func env(name string) string {
	v := os.Getenv(name)
	if v == "" {
		panic(name + " needs to be provided in env")
	}
	return v
}

var (
	LOCAL_NAME = env("REMOTE_HOST")

	EXT_SMTP_USERNAME = env("EXT_SMTP_USERNAME")
	EXT_SMTP_PASSWORD = env("EXT_SMTP_PASSWORD")
	EXT_SMTP_HOST     = env("EXT_SMTP_HOST")
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

type Address struct {
	*mail.Address
	domain string
}

func parseAddress(v string) (*Address, error) {
	e, err := mail.ParseAddress(v)
	if err != nil {
		return nil, err
	}

	domain := strings.Split(e.Address, "@")[1]

	return &Address{
		e,
		domain,
	}, nil
}

func rcptHandler(remoteAddr net.Addr, from string, to string) bool {
	_, err := parseAddress(to)
	if err != nil {
		log.Printf("rcptHandler: failed to parse to: %s\n", err)
		return false
	}
	return true
}

func logger(remoteIP, verb, line string) {
	log.Printf("%s %s %s\n", remoteIP, verb, line)
}

func Run(addr string, handler smtpserver.Handler, rcpt smtpserver.HandlerRcpt) error {
	smtpserver.Debug = true
	srv := &smtpserver.Server{
		Addr:        addr,
		Handler:     handler,
		HandlerRcpt: rcpt,
		Appname:     "fwdr",
		Hostname:    "mailout.mailway.app",
		Timeout:     10 * time.Second,
		LogRead:     logger,
		LogWrite:    logger,
	}
	return srv.ListenAndServe()
}

func findMX(domain string, pref int) (string, error) {
	mxrecords, _ := net.LookupMX(domain)
	for _, mx := range mxrecords {
		fmt.Println(mx.Host, mx.Pref)
		return mx.Host, nil
	}
	// FIXME: implement selection based on pref. Sort by pref and input pref is the
	// top n
	return "", errors.New("No suitable MX found")
}

func updateMailStatus(domain string, uuid string, status int) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	url := fmt.Sprintf("http://127.0.0.1:8081/db/domain/%s/update/%s", domain, uuid)
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

func sendMailgun(from string, to string, data []byte) error {
	auth := netsmtp.PlainAuth("", EXT_SMTP_USERNAME, EXT_SMTP_PASSWORD, EXT_SMTP_HOST)
	return smtpclient.SendMail(LOCAL_NAME, EXT_SMTP_HOST+":587", auth, from, []string{to}, data)
}

func mailHandler(origin net.Addr, from string, to []string, data []byte) {
	for _, to := range to {
		log.Printf("sending mail to %s\n", to)
		msg, err := mail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			log.Printf("failed to parse email: %s\n", err)
			return
		}
		uuid := msg.Header.Get("X-Mailway-Id")
		domain := msg.Header.Get("X-Mailway-domain")
		returnPath := msg.Header.Get("Return-Path")
		file := fmt.Sprintf("/tmp/%s.eml", uuid)

		toAddress, err := parseAddress(to)
		if err != nil {
			log.Printf("ParseAddress: %s\n", err)
			return
		}
		smtpAddr, err := findMX(toAddress.domain, 1)
		if err != nil {
			log.Printf("findMX: %s\n", err)
			return
		}

		log.Printf("Received mail %s from %s for %s\n", uuid, from, toAddress.Address)

		messageIdHeader := fmt.Sprintf("Message-Id: %s@%s\n", uuid, domain)
		data = append([]byte(messageIdHeader), data...)

		signedData := data

		options := dkim.NewSigOptions()
		privateKey, err := ioutil.ReadFile("/etc/ssl/dkim-external.pem")
		check(err)
		options.PrivateKey = privateKey
		options.Domain = domain
		options.Selector = "smtp"
		options.SignatureExpireIn = 3600
		options.Headers = []string{"Content-Type", "To", "Subject", "Message-ID", "Date", "From", "MIME-Version", "Sender"}
		options.AddSignatureTimestamp = true
		options.Canonicalization = "relaxed/relaxed"
		err = dkim.Sign(&signedData, options)
		if err != nil {
			log.Printf("could not sign email: %s\n", err)
			return
		}

		err = smtpclient.SendMail(LOCAL_NAME, smtpAddr+":25", nil, returnPath, []string{to}, signedData)
		if err != nil {
			log.Printf("SendMail: %s\n", err)

			err = sendMailgun(from, to, data)
			if err != nil {
				log.Printf("sendMailgun: %s\n", err)
			} else {
				log.Println("mail sent with mailgun")
				check(updateMailStatus(domain, uuid, 2))
				check(os.Remove(file))
			}
		} else {
			log.Printf("Mail sent with own\n")
			check(updateMailStatus(domain, uuid, 2))
			check(os.Remove(file))
		}
	}
}

func main() {
	if err := Run("127.0.0.1:2525", mailHandler, rcptHandler); err != nil {
		log.Fatal(err)
	}
}
