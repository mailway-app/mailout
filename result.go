package main

import (
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

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
