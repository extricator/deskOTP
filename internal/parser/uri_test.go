// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

package parser

import (
	"strings"
	"testing"
)

// TestParseURI verifies all ParseURI behaviors: TOTP, HOTP, Steam, defaults,
// issuer resolution, percent-decoding, and error cases.
func TestParseURI(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ParsedURI
		wantErr string // substring that must appear in err.Error(); empty means no error
	}{
		{
			name:  "TOTP with all params explicit",
			input: "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
			want: ParsedURI{
				Type:    "totp",
				Issuer:  "GitHub",
				Name:    "user@example.com",
				Secret:  "JBSWY3DPEHPK3PXP",
				Algo:    "SHA256",
				Digits:  8,
				Period:  60,
				Counter: 0,
			},
		},
		{
			name:  "HOTP with counter",
			input: "otpauth://hotp/Test:alice?secret=JBSWY3DPEHPK3PXP&counter=42",
			want: ParsedURI{
				Type:    "hotp",
				Issuer:  "Test",
				Name:    "alice",
				Secret:  "JBSWY3DPEHPK3PXP",
				Algo:    "SHA1",
				Digits:  6,
				Period:  30,
				Counter: 42,
			},
		},
		{
			name:  "Steam type",
			input: "otpauth://steam/Steam:gamer?secret=JBSWY3DPEHPK3PXP",
			want: ParsedURI{
				Type:    "steam",
				Issuer:  "Steam",
				Name:    "gamer",
				Secret:  "JBSWY3DPEHPK3PXP",
				Algo:    "SHA1",
				Digits:  6,
				Period:  30,
				Counter: 0,
			},
		},
		{
			name:  "no label prefix — issuer empty, name is full label",
			input: "otpauth://totp/NoIssuerLabel?secret=JBSWY3DPEHPK3PXP",
			want: ParsedURI{
				Type:    "totp",
				Issuer:  "",
				Name:    "NoIssuerLabel",
				Secret:  "JBSWY3DPEHPK3PXP",
				Algo:    "SHA1",
				Digits:  6,
				Period:  30,
				Counter: 0,
			},
		},
		{
			name:  "query issuer wins over label prefix",
			input: "otpauth://totp/LabelIssuer:account?secret=JBSWY3DPEHPK3PXP&issuer=QueryIssuer",
			want: ParsedURI{
				Type:    "totp",
				Issuer:  "QueryIssuer",
				Name:    "account",
				Secret:  "JBSWY3DPEHPK3PXP",
				Algo:    "SHA1",
				Digits:  6,
				Period:  30,
				Counter: 0,
			},
		},
		{
			name:  "percent-encoded label",
			input: "otpauth://totp/Air%20Canada:user?secret=JBSWY3DPEHPK3PXP",
			want: ParsedURI{
				Type:    "totp",
				Issuer:  "Air Canada",
				Name:    "user",
				Secret:  "JBSWY3DPEHPK3PXP",
				Algo:    "SHA1",
				Digits:  6,
				Period:  30,
				Counter: 0,
			},
		},
		{
			name:  "defaults applied when params absent",
			input: "otpauth://totp/Simple?secret=ABC",
			want: ParsedURI{
				Type:    "totp",
				Issuer:  "",
				Name:    "Simple",
				Secret:  "ABC",
				Algo:    "SHA1",
				Digits:  6,
				Period:  30,
				Counter: 0,
			},
		},
		{
			name:    "non-otpauth scheme",
			input:   "https://example.com",
			wantErr: "expected otpauth scheme",
		},
		{
			name:    "missing secret",
			input:   "otpauth://totp/Test?nosecret=true",
			wantErr: "missing secret",
		},
		{
			name:    "unsupported otp type",
			input:   "otpauth://yandex/Test?secret=ABC",
			wantErr: "unsupported otp type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseURI(tt.input)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseURI() returned nil error, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseURI() error = %q, want it to contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseURI() returned unexpected error: %v", err)
			}

			if got.Type != tt.want.Type {
				t.Errorf("Type = %q, want %q", got.Type, tt.want.Type)
			}
			if got.Issuer != tt.want.Issuer {
				t.Errorf("Issuer = %q, want %q", got.Issuer, tt.want.Issuer)
			}
			if got.Name != tt.want.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.want.Name)
			}
			if got.Secret != tt.want.Secret {
				t.Errorf("Secret = %q, want %q", got.Secret, tt.want.Secret)
			}
			if got.Algo != tt.want.Algo {
				t.Errorf("Algo = %q, want %q", got.Algo, tt.want.Algo)
			}
			if got.Digits != tt.want.Digits {
				t.Errorf("Digits = %d, want %d", got.Digits, tt.want.Digits)
			}
			if got.Period != tt.want.Period {
				t.Errorf("Period = %d, want %d", got.Period, tt.want.Period)
			}
			if got.Counter != tt.want.Counter {
				t.Errorf("Counter = %d, want %d", got.Counter, tt.want.Counter)
			}
		})
	}
}
