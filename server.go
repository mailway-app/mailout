package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/mail"
	netsmtp "net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	config "github.com/mailway-app/config"
	smtpclient "github.com/mailway-app/go-smtp/client"

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

// headers to strip out before sending. In lower case.
var (
	X_MAILGUN_SENDING_IP = []byte("x-mailgun-sending-ip")
	INT_HEADER_PREFIX    = []byte("mw-int-")
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

func sendAltSmtp(from string, to string, data []byte) error {
	auth := netsmtp.PlainAuth("", config.CurrConfig.OutSMTPUsername, config.CurrConfig.OutSMTPPassword, config.CurrConfig.OutSMTPHost)
	port := config.CurrConfig.OutSMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", config.CurrConfig.OutSMTPHost, port)
	return smtpclient.SendMail(config.CurrConfig.InstanceHostname, addr, auth, from, []string{to}, data)
}

// Prepare email to be sent outside
func prepareEmail(mail []byte) ([]byte, error) {
	out := make([]byte, 0)
	newline := []byte{'\r', '\n'}

	scanner := bufio.NewScanner(bytes.NewReader(mail))
	for scanner.Scan() {
		line := scanner.Bytes()
		lowerCaseline := bytes.ToLower(line)
		if bytes.HasPrefix(lowerCaseline, INT_HEADER_PREFIX) ||
			bytes.HasPrefix(lowerCaseline, X_MAILGUN_SENDING_IP) {
			continue // ignore line
		}

		out = append(out, line...)
		out = append(out, newline...)
	}

	if err := scanner.Err(); err != nil {
		return out, errors.Wrap(err, "could not read message")
	}

	return out, nil
}

func mailHandler(origin net.Addr, from string, to []string, in []byte) error {
	for _, to := range to {
		log.Printf("sending mail to %s\n", to)
		msg, err := mail.ReadMessage(bytes.NewReader(in))
		if err != nil {
			log.Printf("failed to parse email: %s\n", err)
			return unknownError
		}
		uuid := msg.Header.Get("Mw-Int-Id")
		domain := msg.Header.Get("Mw-Int-Domain")
		file := fmt.Sprintf("/tmp/%s.eml", uuid)

		toAddress, err := parseAddress(to)
		if err != nil {
			log.Errorf("ParseAddress: %s\n", err)
			return unknownError
		}
		smtpAddr, err := findMX(toAddress.domain, 1)
		if err != nil {
			log.Errorf("findMX: %s\n", err)
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

		err = smtpclient.SendMail(config.CurrConfig.InstanceHostname, smtpAddr+":25", nil, returnPath, []string{to}, signedData)
		if err != nil {
			errDetails, parseErr := parseSendError(err)
			if parseErr != nil {
				log.Warnf("could not parse smtp response: %s. Got: %s", parseErr, err)
			} else {
				log.Infof("SendMail returned %d %d", errDetails.code, errDetails.enhancedCode)
			}

			if errDetails == nil || errDetails.shouldTryAltSmtp() {
				log.Infof("trying with alternative smtp")
				if err := sendAltSmtp(from, to, outMail); err != nil {
					log.Errorf("sendAltSmtp: %s\n", err)
					check(updateMailStatus(config.CurrConfig.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERY_ERROR))
				} else {
					log.Debugf("mail sent with alternative smtp")
					check(updateMailStatus(config.CurrConfig.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERED))
					check(os.Remove(file))
				}
			} else {
				check(updateMailStatus(config.CurrConfig.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERY_ERROR))
			}
		} else {
			log.Printf("Mail sent with own\n")
			check(updateMailStatus(config.CurrConfig.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERED))
			check(os.Remove(file))
		}
	}

	return nil
}

type enhancedCode [3]int

type sendResult struct {
	code         int
	enhancedCode enhancedCode
	msg          string
}

func (r sendResult) isTransientFailure() bool {
	return r.enhancedCode[0] == 4
}
func (r sendResult) isPermanentFailure() bool {
	return r.enhancedCode[0] == 5
}
func (r sendResult) shouldTryAltSmtp() bool {
	// Gmail specific: https://support.google.com/a/answer/3726730?hl=en
	if strings.Contains(r.msg, "this message has been blocked") {
		return false
	}
	// Mailbox Status
	if r.enhancedCode[0] == 5 && r.enhancedCode[1] == 2 {
		return false
	}
	return true
}

func parseSendError(input error) (*sendResult, error) {
	parts := strings.SplitN(input.Error(), " ", 3)

	code, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, "could not parse error code")
	}

	var enhancedCode enhancedCode

	enhancedCodeParts := strings.SplitN(parts[1], ".", 3)
	for i, str := range enhancedCodeParts {
		n, err := strconv.Atoi(str)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse enhanced error code")
		}
		enhancedCode[i] = n
	}
	msg := parts[2]

	return &sendResult{code, enhancedCode, msg}, nil
}

func main() {
	if err := config.Init(); err != nil {
		log.Fatalf("failed to init config: %s", err)
	}
	if config.CurrConfig.InstanceHostname == "" {
		log.Fatal("instance hostname is needed")
	}

	if err := Run("127.0.0.1:2525", mailHandler, rcptHandler); err != nil {
		log.Fatal(err)
	}
}
