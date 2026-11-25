package totp_test

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func underflowRegressionSecret() string {
	return base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
}

func underflowRegressionCode(t *testing.T, secret string, counter uint64) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)
	return code
}

func TestValidateCustomSkipsWrappedCounterNearEpochRegression(t *testing.T) {
	secret := underflowRegressionSecret()
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	}
	when := time.Unix(0, 0).UTC()

	currentCode, err := totp.GenerateCodeCustom(secret, when, opts)
	require.NoError(t, err)

	valid, err := totp.ValidateCustom(currentCode, secret, when, opts)
	require.NoError(t, err)
	require.True(t, valid)

	wrappedCounter := ^uint64(0)
	wrappedCode := underflowRegressionCode(t, secret, wrappedCounter)
	valid, err = totp.ValidateCustom(wrappedCode, secret, when, opts)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestValidateCustomBackwardWindowStopsAtZeroRegression(t *testing.T) {
	secret := underflowRegressionSecret()
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      3,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	}
	when := time.Unix(2*int64(opts.Period), 0).UTC()

	zeroCounterCode := underflowRegressionCode(t, secret, 0)
	valid, err := totp.ValidateCustom(zeroCounterCode, secret, when, opts)
	require.NoError(t, err)
	require.True(t, valid)

	wrappedCode := underflowRegressionCode(t, secret, ^uint64(0))
	valid, err = totp.ValidateCustom(wrappedCode, secret, when, opts)
	require.NoError(t, err)
	require.False(t, valid)
}
