package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSendError(t *testing.T) {
	{
		input := errors.New(`550 5.7.1 [ip      12] a\n5.7.1b,\n5.7.1 c\n5.7.1  this message has been blocked\n5.7.1\n`)
		res, err := parseSendError(input)
		assert.Nil(t, err)
		assert.Equal(t, res, &sendResult{
			code:         550,
			enhancedCode: enhancedCode{5, 7, 1},
			msg:          `[ip      12] a\n5.7.1b,\n5.7.1 c\n5.7.1  this message has been blocked\n5.7.1\n`,
		})
		assert.False(t, res.isTransientFailure())
		assert.True(t, res.isPermanentFailure())
		assert.False(t, res.shouldTryAltSmtp())
	}

	{
		input := errors.New(`552 5.2.2 a`)
		res, err := parseSendError(input)
		assert.Nil(t, err)
		assert.Equal(t, res, &sendResult{
			code:         552,
			enhancedCode: enhancedCode{5, 2, 2},
			msg:          `a`,
		})
		assert.False(t, res.isTransientFailure())
		assert.True(t, res.isPermanentFailure())
		assert.False(t, res.shouldTryAltSmtp())
	}
}

func TestParseSendErrorShouldTryAltSmtp(t *testing.T) {
	{
		input := errors.New(`550 5.7.1 a`)
		res, err := parseSendError(input)
		assert.Nil(t, err)
		assert.Equal(t, res, &sendResult{
			code:         550,
			enhancedCode: enhancedCode{5, 7, 1},
			msg:          `a`,
		})
		assert.False(t, res.isTransientFailure())
		assert.True(t, res.isPermanentFailure())
		assert.True(t, res.shouldTryAltSmtp())
	}

	{
		input := errors.New(`450 4.2.1 a`)
		res, err := parseSendError(input)
		assert.Nil(t, err)
		assert.Equal(t, res, &sendResult{
			code:         450,
			enhancedCode: enhancedCode{4, 2, 1},
			msg:          `a`,
		})
		assert.True(t, res.isTransientFailure())
		assert.False(t, res.isPermanentFailure())
		assert.True(t, res.shouldTryAltSmtp())
	}
}
