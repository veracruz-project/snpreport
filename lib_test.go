//! tests for the AMS SEV SNP Attestation Report module
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

package snpreport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	pseudoRand "math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	envSeedValue := os.Getenv("GO_DOC_SEED")

	var seed int64
	var err error
	if envSeedValue != "" {
		seed, err = strconv.ParseInt(envSeedValue, 10, 64)
		if err != nil {
			panic("Error: Invalid input for seed")
		}
	} else {
		seed = time.Now().UnixNano()
	}
	fmt.Printf("To repeat this test, set an environment variable GO_DOC_SEED to %v\n", seed)
	pseudoRand.Seed(seed)
}

func generateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate key:%v", err)
	}
	pubKey := key.Public()
	convertedPubKey := pubKey.(*ecdsa.PublicKey)
	return key, convertedPubKey, nil
}

func generateRandomSlice(size int32) []byte {
	result := make([]byte, size)
	pseudoRand.Read(result)
	return result
}

func Test_AuthenticateReport_ok(t *testing.T) {
	privKey, pubKey, err := generateKeys()
	if err != nil {
		t.Fatalf("gnereateKeys failed:%v\n", err)
	}
	reportData := generateRandomSlice(64)
	reportBuf, err := GenerateReport(reportData, *privKey)
	if err != nil {
		t.Fatalf("generateReport failed:%v\n", err)
	}

	report, err := AuthenticateReport(reportBuf, pubKey)
	if err != nil {
		t.Errorf("Failed to authenticate document:%v\n", err)
	}
	assert.Equal(t, report.ReportData, reportData)
}

func Test_AuthenticateReport_bad_signature(t *testing.T) {
	privKey, pubKey, err := generateKeys()
	if err != nil {
		t.Fatalf("gnereateKeys failed:%v\n", err)
	}
	reportData := generateRandomSlice(64)
	reportBuf, err := GenerateReport(reportData, *privKey)
	if err != nil {
		t.Fatalf("generateReport failed:%v\n", err)
	}
	// modify the data so the signature's not valid
	reportBuf[2] = reportBuf[2] ^ reportBuf[2]

	_, err = AuthenticateReport(reportBuf, pubKey)
	assert.EqualError(t, err, `AuthenticateReport::Verify failed: verification error`)
}
