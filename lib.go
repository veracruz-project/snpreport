//! A go module for authenticating and parsing AMD SEV SNP Attestation Reports
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
	"fmt"
)

type TcbVersion struct {
	BootLoader byte
	Tee byte
	reserved [4]byte
	Snp byte
	Microcode byte
}

type SigStruct struct {
	R [72]byte
	S [72]byte
	reserved [512-144]byte
}

type AttestationReport struct {
	Version uint32
	GuestSvn uint32
	Policy uint64
	FamilyId [16]byte
	ImageId [16]byte
	Vmpl uint32
	SignatureAlgo uint32
	PlatformVersion TcbVersion
	PlatformInfo uint64
	Flags uint32
	reserved0 uint32
	ReportData [64]byte
	Measurement [48]byte
	HostData [32]byte
	IdKeyDigest [48]byte
	AuthorKeyDigest [48]byte
	ReportId [32]byte
	ReportIdMa [32]byte
	ReportedTcb TcbVersion
	reserved1 [24]byte
	ChipId [64]byte
	reserved2 [192]byte
	Signature SigStruct
}

/// Authenticate an AMD SEV SNP Attestation Report with the provided public key.
/// If authentication passes, return the generated AttestationReport representing the fields
/// from the provided report
/// data - the report data to be authenticated
/// public_key - The key to be used to authenticate the report
func AuthenticateReport(data []byte, publicKey *ecdsa.PublicKey) (*AttestationReport, error) {
	return nil, fmt.Errorf("snpreport.AuthenticateReport not yet implemented")
}

/// Generate a fake AMD SEV SNP Attestation Report, signed by the provided key with the provided data fields incorporated into the report
/// This interface is useful for testing. Beyond that, there should be no reason for you to generate your own attestation report this way
func GenerateReport(reportData []byte, signingKey ecdsa.PrivateKey) ([]byte, error) {
	return nil, fmt.Errorf("snpreport.GenerateDocument not yet implemented")
}

