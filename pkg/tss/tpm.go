// Copyright (c) 2018, Google LLC All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package tss

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	mssimCommandPort  = "2321"
	mssimPlatformPort = "2322"
	mssimURLScheme    = "mssim"
)

// TCGVendorID represents a unique TCG manufacturer code.
// The canonical reference used is located at:
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.01-Revision-1.00.pdf
type TCGVendorID uint32

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1229081856: "IBM",
	1213220096: "HPE",
	1297303124: "Microsoft",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576515: "SMSC",
	1398033696: "ST Microelectronics",
	1397576526: "Samsung",
	1397641984: "Sinosun",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1380926275: "Fuzhou Rockchip",
	1196379975: "Google",
}

type TPM20Info struct {
	Manufacturer TCGVendorID
	Family       string
	SpecRevision string
}

var ECCPublicKey = tpm2.Public{
	Type:    tpm2.AlgECC,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
	AuthPolicy: []byte{},
	ECCParameters: &tpm2.ECCParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		CurveID: tpm2.CurveNISTP256,
	},
}

func RunCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func Concat(chunks ...[]byte) []byte {
	return bytes.Join(chunks, nil)
}

func EncodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return Concat(size, res), nil
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{tpm2.RCFmt1(code & 0x3f), tpm2.RCIndex((code & 0x700) >> 8)}
}

func encodeStartAuthSession(tpmKey, bindKey tpmutil.Handle, nonceCaller, secret tpmutil.U16Bytes, se tpm2.SessionType, sym, hashAlg tpm2.Algorithm) ([]byte, error) {
	ha, err := tpmutil.Pack(tpmKey, bindKey)
	if err != nil {
		return nil, err
	}
	params, err := tpmutil.Pack(nonceCaller, secret, se, sym, hashAlg, hashAlg)
	if err != nil {
		return nil, err
	}
	return Concat(ha, params), nil
}

func decodeStartAuthSession(in []byte) (tpmutil.Handle, []byte, error) {
	var handle tpmutil.Handle
	var nonce tpmutil.U16Bytes
	if _, err := tpmutil.Unpack(in, &handle, &nonce); err != nil {
		return 0, nil, err
	}
	return handle, nonce, nil
}

func OpenNetTPM(url *url.URL) (io.ReadWriteCloser, error) {
	var rwc io.ReadWriteCloser
	sock, err := net.Dial("tcp", url.Hostname()+":"+url.Port())
	if err != nil {
		return nil, err
	}
	rwc = io.ReadWriteCloser(sock)
	_ = tpm2.Startup(rwc, tpm2.StartupClear)

	return rwc, nil
}

func (id TCGVendorID) String() string {
	return vendors[id]
}

func Property(conn io.ReadWriteCloser, prop uint32) (uint32, error) {
	caps, _, err := tpm2.GetCapability(conn, tpm2.CapabilityTPMProperties, 1, prop)
	if err != nil {
		return 0, err
	}

	if len(caps) == 0 {
		return 0, fmt.Errorf("TPM GetCapability returned invalid data")
	}
	if p, ok := caps[0].(tpm2.TaggedProperty); !ok || uint32(p.Tag) != prop {
		return 0, fmt.Errorf("TPM GetCapability returned invalid data")
	} else {
		return p.Value, nil
	}
}

func ReadTPM2VendorAttributes(tpm io.ReadWriteCloser) (*TPM20Info, error) {
	manu, err := Property(tpm, uint32(tpm2.Manufacturer))
	if err != nil {
		return nil, err
	}
	family, err := Property(tpm, uint32(tpm2.FamilyIndicator))
	if err != nil {
		return nil, err
	}
	spec, err := Property(tpm, uint32(tpm2.SpecRevision))
	if err != nil {
		return nil, err
	}
	return &TPM20Info{
		Manufacturer: TCGVendorID(manu),
		Family:       fmt.Sprintf("%d", family),
		SpecRevision: fmt.Sprintf("%d", spec),
	}, nil
}

// StartAuthSession initializes a session object.
// Returns session handle and the initial nonce from the TPM.
func StartAuthSession(rw io.ReadWriter, tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se tpm2.SessionType, sym, hashAlg tpm2.Algorithm) (tpmutil.Handle, []byte, error) {
	Cmd, err := encodeStartAuthSession(tpmKey, bindKey, nonceCaller, secret, se, sym, hashAlg)
	if err != nil {
		return 0, nil, err
	}
	resp, err := RunCommand(rw, tpm2.TagNoSessions, tpm2.CmdStartAuthSession, tpmutil.RawBytes(Cmd))
	if err != nil {
		return 0, nil, err
	}
	return decodeStartAuthSession(resp)
}
