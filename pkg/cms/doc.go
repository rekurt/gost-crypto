// Package cms implements CMS (Cryptographic Message Syntax) / PKCS#7 operations
// with GOST R 34.10-2012 digital signatures, backed by CryptoPro CAdES (CAdES-BES).
//
// CMS SignedData is the standard format for digitally signed documents in
// Russian electronic document management systems (ЭДО). This package supports
// both attached and detached signatures.
//
// # Signing
//
//	signed, _ := cms.Sign(priv, cert, data, cms.SignOptions{Detached: true})
//	der, _ := signed.DER()
//
// # Verification
//
//	sig, _ := cms.ParseDER(signatureDER)
//	err := sig.Verify(originalData, cms.VerifyOptions{NoCertVerify: true})
//
// # Standards
//
// RFC 5652 (CMS), RFC 4490 (GOST CMS), GOST R 34.10-2012, GOST R 34.11-2012.
package cms
