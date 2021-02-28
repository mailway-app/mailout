package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"time"

	config "github.com/mailway-app/config"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// headers to strip out before sending. In lower case.
var (
	X_MAILGUN_SENDING_IP = []byte("x-mailgun-sending-ip")
	INT_HEADER_PREFIX    = []byte("mw-int-")
)

func findPort(host string) (int, error) {
	if testPort(host, 25) {
		return 25, nil
	}
	if testPort(host, 587) {
		return 587, nil
	}
	if testPort(host, 465) {
		return 465, nil
	}
	if testPort(host, 2525) {
		return 2525, nil
	}
	return 0, errors.New("no open SMTP ports")
}

type EmailServer struct {
	host string
	port uint16
}

func (s EmailServer) String() string {
	return fmt.Sprintf("%s:%d", s.host, s.port)
}

func findMX(domain string, pref int) (EmailServer, error) {
	mxrecords, err := net.LookupMX(domain)
	if err != nil {
		log.Debugf("MX lookup failed: %s", err)
	}
	for _, mx := range mxrecords {
		port, err := findPort(mx.Host)
		if err != nil {
			log.Warnf("failed to find port for %s: %s", mx.Host, err)
			continue
		}
		server := EmailServer{host: mx.Host, port: uint16(port)}
		log.Infof("selected smtp server %s", server)
		return server, nil
	}
	// FIXME: implement selection based on pref. Sort by pref and input pref is the
	// top n

	cname, srvAddrs, err := net.LookupSRV("submission", "tcp", domain)
	if err != nil {
		log.Debugf("SRV lookup failed: %s", err)
	}
	if len(srvAddrs) > 0 {
		for _, record := range srvAddrs {
			server := EmailServer{host: record.Target, port: record.Port}
			log.Infof("%s selected %s", cname, server)
			return server, nil
		}
	}

	return EmailServer{}, errors.New("No suitable MX found")
}

func isInsecureMX(host string) bool {
	list := config.CurrConfig.MailoutInsecureMX
	for _, b := range list {
		if b+"." == host {
			return true
		}
	}
	return false
}

func sendAltSmtp(domain string, from string, to string, data []byte) error {
	if rateAltSMTPLimiter.GetCount(domain) > uint(RATE_ALT_SMTP_LIMIT) {
		log.Errorf("domain %s rate limited for alt smtp", domain)
		return rateError
	}
	rateAltSMTPLimiter.Inc(domain)

	auth := netsmtp.PlainAuth("", config.CurrConfig.OutSMTPUsername, config.CurrConfig.OutSMTPPassword, config.CurrConfig.OutSMTPHost)
	port := config.CurrConfig.OutSMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", config.CurrConfig.OutSMTPHost, port)
	client, err := Dial(config.CurrConfig.InstanceHostname, addr)
	if err != nil {
		return errors.Wrap(err, "could not connect to SMTP")
	}
	return SendMail(client, addr, auth, from, []string{to}, data, false)
}

func testPort(host string, port int) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		log.Debugf("failed to connect to %s:%d: %s", host, port, err)
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

// Send an email
// Signed data and data are seperated because the we give the unsigned email to the alternative SMTP and send the signed ourselves.
func sendMailToServer(
	server EmailServer,
	returnPath string,
	from string,
	to string,
	signedData []byte,
	data []byte,
	domain string,
	uuid string,
) error {
	var client *Client
	var err error

	// On port 465 try to connect via TLS first
	if server.port == 465 {
		client, err = DialTLS(config.CurrConfig.InstanceHostname, server.String())
		if err != nil {
			log.Debugf("failed to connect over TLS: %s", err)
		}
	}
	// if client doesn't exit or failed to create so far, create it now over clear
	if client == nil {
		client, err = Dial(config.CurrConfig.InstanceHostname, server.String())
		if err != nil {
			return errors.Wrap(err, "could not connect to SMTP")
		}
	}
	defer client.Close()

	disallowTLS := isInsecureMX(server.host)
	if disallowTLS {
		log.Debugf("disallow TLS for %s", server.host)
	}
	err = SendMail(
		client, server.String(), nil,
		returnPath, []string{to}, signedData, disallowTLS)

	// if we managed to send from the current machine, stop here. Otherwise
	// try other alternatives.
	if err == nil {
		log.Printf("Mail sent with own\n")
		return nil
	}

	errDetails, parseErr := parseSendError(err)
	if parseErr != nil {
		log.Warnf("could not parse smtp response: %s. Got: %s", parseErr, err)
	} else {
		log.Infof("SendMail returned %d %d", errDetails.code, errDetails.enhancedCode)
	}

	if errDetails == nil || errDetails.shouldTryAltSmtp() {
		log.Infof("trying with alternative smtp")
		err := sendAltSmtp(domain, from, to, data)
		if err == nil {
			log.Debugf("mail sent with alternative smtp")
			return nil
		}
		log.Errorf("sendAltSmtp: %s\n", err)
		return err
	}

	return nil
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
