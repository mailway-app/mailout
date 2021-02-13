package main

import (
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

	mconfig "github.com/mailway-app/config"
	smtpclient "github.com/mailway-app/go-smtp/client"

	"github.com/mhale/smtpd"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	dkim "github.com/toorop/go-dkim"
)

var (
	config       *mconfig.Config
	unknownError = errors.New("unknown error")
)

const (
	INT_HEADER_PREFIX = "Mw-Int-"

	// MAIL_STATUS_RECEIVED  = 0
	// MAIL_STATUS_PROCESSED = 1
	MAIL_STATUS_DELIVERED = 2
	// MAIL_STATUS_SPAM = 3
	MAIL_STATUS_DELIVERY_ERROR = 4
)

var HEADERS_TO_REMOVE = []string{
	"X-Mailgun-Sending-Ip",
}

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
		Hostname:    config.InstanceHostname,
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
	auth := netsmtp.PlainAuth("", config.OutSMTPUsername, config.OutSMTPPassword, config.OutSMTPHost)
	port := config.OutSMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", config.OutSMTPHost, port)
	return smtpclient.SendMail(config.InstanceHostname, addr, auth, from, []string{to}, data)
}

func shouldRemoveHeader(n string) bool {
	for _, b := range HEADERS_TO_REMOVE {
		if strings.EqualFold(n, b) {
			return true
		}
	}
	return false
}

func mailToString(m *mail.Message) string {
	headers := make([]string, 0)
	for k, vs := range m.Header {
		if !strings.HasPrefix(k, INT_HEADER_PREFIX) && !shouldRemoveHeader(k) {
			for _, v := range vs {
				headers = append(headers, fmt.Sprintf("%s: %s", k, v))
			}
		}
	}
	out := strings.Join(headers, "\r\n")
	out += "\r\n\r\n"

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(m.Body); err != nil {
		log.Errorf("buffer ReadFrom error: %s", err)
	}
	out += buf.String()

	return out
}

func mailHandler(origin net.Addr, from string, to []string, in []byte) error {
	for _, to := range to {
		log.Printf("sending mail to %s\n", to)
		msg, err := mail.ReadMessage(bytes.NewReader(in))
		if err != nil {
			log.Printf("failed to parse email: %s\n", err)
			return unknownError
		}
		uuid := msg.Header.Get("X-Mailway-Id")
		domain := msg.Header.Get("X-Mailway-domain")
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

		msg.Header["Message-Id"] = []string{fmt.Sprintf("%s@%s", uuid, domain)}

		serializedTo := strings.ReplaceAll(to, "@", "=")
		returnPath := fmt.Sprintf("bounces+%s+%s@%s", uuid, serializedTo, domain)
		msg.Header["Return-Path"] = []string{returnPath}

		outMail := mailToString(msg)
		signedData := []byte(outMail)

		if _, err := os.Stat(config.OutDKIMPath); !os.IsNotExist(err) {
			options := dkim.NewSigOptions()
			privateKey, err := ioutil.ReadFile(config.OutDKIMPath)
			check(err)
			options.PrivateKey = privateKey
			options.Domain = domain
			options.Algo = "rsa-sha256"
			options.Selector = "smtp"
			options.SignatureExpireIn = 3600
			options.Headers = []string{"Content-Type", "To", "Subject", "Message-Id", "Date", "From", "MIME-Version", "Sender"}
			options.AddSignatureTimestamp = true
			options.Canonicalization = "relaxed/relaxed"
			err = dkim.Sign(&signedData, options)
			if err != nil {
				log.Printf("could not sign email: %s\n", err)
				return unknownError
			}
		} else {
			log.Warnf("couldn't sign email because key was not found at: %s", config.OutDKIMPath)
		}

		err = smtpclient.SendMail(config.InstanceHostname, smtpAddr+":25", nil, returnPath, []string{to}, signedData)
		if err != nil {
			errDetails, parseErr := parseSendError(err)
			if parseErr != nil {
				log.Warnf("could not parse smtp response: %s. Got: %s", parseErr, err)
			} else {
				log.Infof("SendMail returned %d %d", errDetails.code, errDetails.enhancedCode)
			}

			if errDetails == nil || errDetails.shouldTryAltSmtp() {
				log.Infof("trying with alternative smtp")
				if err := sendAltSmtp(from, to, []byte(outMail)); err != nil {
					log.Errorf("sendAltSmtp: %s\n", err)
					check(updateMailStatus(config.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERY_ERROR))
				} else {
					log.Debugf("mail sent with alternative smtp")
					check(updateMailStatus(config.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERED))
					check(os.Remove(file))
				}
			} else {
				check(updateMailStatus(config.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERY_ERROR))
			}
		} else {
			log.Printf("Mail sent with own\n")
			check(updateMailStatus(config.ServerJWT, domain, uuid, MAIL_STATUS_DELIVERED))
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
	c, err := mconfig.Read()
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(c.GetLogLevel())
	log.SetFormatter(c.GetLogFormat())

	if c.InstanceHostname == "" {
		log.Fatal("instance hostname is needed")
	}
	config = c

	if err := Run("127.0.0.1:2525", mailHandler, rcptHandler); err != nil {
		log.Fatal(err)
	}
}
