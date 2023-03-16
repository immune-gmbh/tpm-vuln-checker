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
	swtpmURL = "tcp://127.0.0.1:2321"
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

type TCGFamily uint32

var families = map[TCGFamily]string{
	841887744: "2.0",
}

type TCGSpecRevision uint32
type TCGFirmwareVersion uint32
type TCGVendorString uint32
type TCGYear uint32

type TPM20Info struct {
	Manufacturer TCGVendorID
	Family       TCGFamily
	SpecRevision TCGSpecRevision
	FWVersion1   TCGFirmwareVersion
	FWVersion2   TCGFirmwareVersion
	VendorData1  TCGVendorString
	VendorData2  TCGVendorString
	VendorData3  TCGVendorString
	VendorData4  TCGVendorString
	Year         TCGYear
}

func (t *TPM20Info) SpecYear() string {
	tmp := fmt.Sprintf("%d", t.Year)
	return fmt.Sprintf("%c%c%c%c", tmp[0], tmp[1], tmp[2], tmp[3])
}

func (t *TPM20Info) Type() string {
	switch t.Family {
	case 1095582720:
	case 1229870147:
		return "fTPM"
	}
	return "dTPM"
}

func (t *TPM20Info) Version() string {
	return families[t.Family]
}

func (t *TPM20Info) Specification() string {
	tmp := fmt.Sprintf("%d", t.SpecRevision)
	return fmt.Sprintf("%c.%s", tmp[0], tmp[1:])
}

func (t *TPM20Info) FirmwareVersion() string {
	var firmwareVersion string
	version1 := fmt.Sprintf("%d", t.FWVersion1)
	version2 := fmt.Sprintf("%d", t.FWVersion1)
	if t.FWVersion1 != 0 {
		firmwareVersion = fmt.Sprintf("%c.%s", version1[0], version1[1:])
	}
	if t.FWVersion2 != 0 {
		firmwareVersion += fmt.Sprintf(" - %c.%s", version2[0], version2[1:])
	}
	return firmwareVersion
}

func (t *TPM20Info) Vendor() string {
	return vendors[t.Manufacturer]
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

var RSAPublicKey = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
	AuthPolicy: []byte{},
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		KeyBits: 2048,
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

func IsTPM2(tpm io.ReadWriteCloser) bool {
	_, err := Property(tpm, uint32(tpm2.FamilyIndicator))
	return err == nil
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
	version1, err := Property(tpm, uint32(tpm2.FirmwareVersion1))
	if err != nil {
		return nil, err
	}
	version2, err := Property(tpm, uint32(tpm2.FirmwareVersion2))
	if err != nil {
		return nil, err
	}
	vendor1, err := Property(tpm, uint32(tpm2.VendorString1))
	if err != nil {
		return nil, err
	}
	vendor2, err := Property(tpm, uint32(tpm2.VendorString2))
	if err != nil {
		return nil, err
	}
	vendor3, err := Property(tpm, uint32(tpm2.VendorString3))
	if err != nil {
		return nil, err
	}
	vendor4, err := Property(tpm, uint32(tpm2.VendorString4))
	if err != nil {
		return nil, err
	}
	year, err := Property(tpm, uint32(tpm2.SpecYear))
	if err != nil {
		return nil, err
	}
	return &TPM20Info{
		Manufacturer: TCGVendorID(manu),
		Family:       TCGFamily(family),
		SpecRevision: TCGSpecRevision(spec),
		FWVersion1:   TCGFirmwareVersion(version1),
		FWVersion2:   TCGFirmwareVersion(version2),
		VendorData1:  TCGVendorString(vendor1),
		VendorData2:  TCGVendorString(vendor2),
		VendorData3:  TCGVendorString(vendor3),
		VendorData4:  TCGVendorString(vendor4),
		Year:         TCGYear(year),
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

func NewTPM(emulator bool) (io.ReadWriteCloser, error) {
	var err error
	var rwc io.ReadWriteCloser
	if emulator {
		var url *url.URL
		url, err = url.Parse(swtpmURL)
		if err != nil {
			return nil, err
		}
		rwc, err = OpenNetTPM(url)
		if err != nil {
			return nil, err
		}
	} else {
		rwc, err = OpenTPM()
		if err != nil {
			return nil, err
		}
	}
	return rwc, nil
}

func FlushAllHandles(tpm io.ReadWriteCloser) error {
	vals, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityHandles, 100, uint32(tpm2.HandleTypeHMACSession)<<24)
	if err != nil {
		return err
	}

	if len(vals) > 0 {
		for _, handle := range vals {
			switch t := handle.(type) {
			default:

			case tpmutil.Handle:
				tpm2.FlushContext(tpm, t)
			}
		}
	}
	return nil
}
