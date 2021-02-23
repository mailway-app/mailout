package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	config "github.com/mailway-app/config"

	"github.com/mhale/smtpd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	dkim "github.com/toorop/go-dkim"
)

var (
	unknownError = errors.New("unknown error")
)

const (
	// MAIL_STATUS_RECEIVED  = 0
	// MAIL_STATUS_PROCESSED = 1
	MAIL_STATUS_DELIVERED = 2
	// MAIL_STATUS_SPAM = 3
	MAIL_STATUS_DELIVERY_ERROR = 4
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
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

func Run(addr string, handler smtpd.Handler, rcpt smtpd.HandlerRcpt) error {
	smtpd.Debug = true
	srv := &smtpd.Server{
		Addr:        addr,
		Handler:     handler,
		HandlerRcpt: rcpt,
		Appname:     "mailout",
		Hostname:    config.CurrConfig.InstanceHostname,
		Timeout:     3 * time.Minute,
		LogRead:     logger,
		LogWrite:    logger,
	}
	return srv.ListenAndServe()
}

func mailHandler(origin net.Addr, from string, to []string, in []byte) error {
	for _, to := range to {
		log.Printf("sending mail to %s", to)
		msg, err := mail.ReadMessage(bytes.NewReader(in))
		if err != nil {
			log.Errorf("failed to parse email: %s", err)
			return unknownError
		}
		uuid := msg.Header.Get("Mw-Int-Id")
		domain := msg.Header.Get("Mw-Int-Domain")
		file := fmt.Sprintf("/tmp/%s.eml", uuid)

		toAddress, err := parseAddress(to)
		if err != nil {
			log.Errorf("ParseAddress: %s", err)
			return unknownError
		}
		smtpServer, err := findMX(toAddress.domain, 1)
		if err != nil {
			log.Errorf("could not findMX: %s", err)
			return unknownError
		}

		serializedTo := strings.ReplaceAll(to, "@", "=")
		returnPath := fmt.Sprintf("bounces+%s+%s@%s", uuid, serializedTo, domain)

		outMail, err := prepareEmail(in)
		if err != nil {
			return errors.Wrap(err, "could not prepare email for sending")
		}
		signedData := outMail

		if _, err := os.Stat(config.CurrConfig.OutDKIMPath); !os.IsNotExist(err) {
			options := dkim.NewSigOptions()
			privateKey, err := ioutil.ReadFile(config.CurrConfig.OutDKIMPath)
			check(err)
			options.PrivateKey = privateKey
			options.Domain = domain
			options.Algo = "rsa-sha256"
			options.Selector = "smtp"
			options.SignatureExpireIn = 3600
			options.Headers = []string{"Content-Type", "To", "Subject", "Date", "From", "MIME-Version", "Sender"}
			options.AddSignatureTimestamp = true
			options.Canonicalization = "relaxed/relaxed"
			err = dkim.Sign(&signedData, options)
			if err != nil {
				log.Errorf("could not sign email: %s\n", err)
				return unknownError
			}
		} else {
			log.Warnf("couldn't sign email because key was not found at: %s", config.CurrConfig.OutDKIMPath)
		}

		err = sendMailToServer(
			smtpServer, returnPath, from, to, signedData, outMail, domain, uuid)
		if err != nil {
			check(updateMailStatus(
				config.CurrConfig.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERY_ERROR))
			return errors.Wrap(err, "could not send email")
		}
		check(updateMailStatus(config.CurrConfig.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERED))
		check(os.Remove(file))
	}

	return nil
}

func main() {
	if err := config.Init(); err != nil {
		log.Fatalf("failed to init config: %s", err)
	}
	if config.CurrConfig.InstanceHostname == "" {
		log.Fatal("instance hostname is needed")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", config.CurrConfig.PortMailout)
	if err := Run(addr, mailHandler, rcptHandler); err != nil {
		log.Fatal(err)
	}
}
