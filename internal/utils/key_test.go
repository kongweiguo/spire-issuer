package utils

import (
	"reflect"
	"testing"
)

var (
	privateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHFNzzBbVgRdnYpQt
R3hW3/r9K3FYBeAcJzqzAJxDs2yhRANCAARqtyE1TKLNWS2TmDuzjbpQMP8uOiM6
ae8GduxjQQmWsdD9maC6VSFXGKWyGq9whztvSYBL503Xs7FsC44mxQLY
-----END PRIVATE KEY-----`)

	privateKeyEC = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKrlnlpqtCsJ/ENxt8DmE6qPkZHb9lHxgZOaNKDJv2TkoAoGCCqGSM49
AwEHoUQDQgAE10c+FffrvuAwpQla2IUMp9kQArDaC0mP+qelxDBIm/NwXNFz6Lub
TvQGSju3QeWBMW/9PDUr3lYCVcMUGz9OmQ==
-----END EC PRIVATE KEY-----`)

	privateKeyRSA = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDNp/k4/7bK6teo
jOXJiiif/LDvMsbJ+83R5xYCAbIAR4q8QRVUPyJ5ODkiMk/ODFRsJI5QAu2oYQGP
2IfQygl+KfyANv5OxzUwifDwfoHTwjm/b2g0ZsYBXW9+3fCx1+gQqWdRqGZVuBmk
pbld18ra2uDn4PV0Z+WymafM8COA6TH+NcctOXqy3ouaeFntKSu1h8pdLHWGjl9k
YY6xCYzGH6JE6R23MyHTVLe942r9m0zAe+liIVnNJjJaqWHUy0yX31R9IviZ7pWK
Qh1HICgIEaPQV384ueVl4rx6GKuwHUqpFeXhE/jdJyPahADjV/UHCihBolrG2h1d
bQ0ZzgY7AgMBAAECggEALOR38MtROaZeATsQhhgUmifs76oj3r+KxEEveqyoEIuN
a17BqyxE+DUfs6lL5mymmRy5vBmHi3PxhVb8/sS7ocDEj7BxfvzZTYkvATB8Yp9J
P9Kv6pBstKuSxRzph8jbrZdtKFQcUqXnYxuSBTwv2ephofxnWEu9xmjoSkI5XdAl
S1g9QsPWYjMcpP5I0yR0PScIsBxucKUqlD7GJGmwv5R00VsUJe+NAbG+dBpiHYt/
okKw5dtzMK6gpM+PqBv4zlI0QX38zPIjk/aFNxv6bhTUfjhGQzbutO05fSobPp3q
+CsfFbst4VIQOF3/+amuO9oNJUzcpAzocH10oCVLsQKBgQD4uf5wFs8A3Qdp+cxM
RDOob5ahh+8jwl1yTmS2P5mEJFpF1OHEQ4HZkqWLd0g/6PZgOxE1VW30zlRWSBUl
PlRLd0BN5gEKkG4s/nOY6/aEwqj/UezAq7RQcKvv8Yncqa80i3dTDIpJLU/qW0zP
/F+p5P4EyE9/OsW8fmcYY3SoNQKBgQDTq4xBz5HJpP9Fjt5E0kXMimt0OGQtNNOj
OkDyAtoguyjiOI6tXAFluH418Q4VW57/YukEtWecLhCTCXL666ZWTOj93P0Y96lp
1Sw6UJ6IkkLpFTgFvqPX0IgIcAOCh9vSy3IjAnNcXFh3sNnrFWUF2n/vO7r4KYY3
C14xKtgirwKBgQC4j5sDpYkZBOnZc2hrNzh1xceqOOn0SOd6SD1nFq5dZXQu2RZl
wgn6XlzErlBITB91rJ7KSof63ZerJnW6WxPFo8lthDxFkIKQlIdGc+FLBf7M5ged
uEtmXRTYSQyZVrgRb2OtlmKOhjcEmZbXxldeA/ORrOmAaSYNBmaNrE8F+QKBgQCQ
itfXZPgoG50aEcqkcnapi2h/T7bQy/8tuqz41ou/yC7N9FMx/N8TaF3/VeIJIay8
tv1qcroTA73bupsiz+KhkhmUqeDHuO+eTqzKEZ2Ao2g/pHbCLYHS8RrDsEIlU8L/
+l+xmo3OZ10eNs1I5C49Rg0Q/9fYePqnAgNLTfeUDwKBgAtMFNN8rEurHHjEHxfQ
dMwofSGmtHkdNzs2ufEyGgYD1kYxV1QcEctq2wM/qMkHLK87DPdhoU9TaknUCifW
UPtAmfxtIJecacwx28vMLbW64hzOv+AHBhEI5UY1bapEBUTCgkf5RsWGgfAOSN55
NyNNQJBEstV4Sap5Q6/VZGLX
-----END PRIVATE KEY-----`)
)

func TestParsePrivateKeyPEM(t *testing.T) {

	tests := []struct {
		name    string
		pemPriv []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:    "privateKey",
			pemPriv: privateKey,
			wantErr: false,
		},
		{
			name:    "privateKeyEC",
			pemPriv: privateKeyEC,
			wantErr: false,
		},
		{
			name:    "privateKeyRSA",
			pemPriv: privateKeyRSA,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := ParsePrivateKeyPEM(tt.pemPriv)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKeyPEM() name:%s, error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}

			t.Logf("name:%s. key type:%s", tt.name, reflect.TypeOf(gotKey).String())
		})
	}
}
