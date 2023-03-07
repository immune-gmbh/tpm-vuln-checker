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
package cve

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/tss"
)

func hex2int(hexStr string) uint64 {
	cleaned := strings.Replace(hexStr, "0x", "", -1)
	result, _ := strconv.ParseUint(cleaned, 16, 64)
	return uint64(result)
}

func parserParameterError(err error) (*tpm2.ParameterError, error) {
	var paramErr tpm2.ParameterError
	strErr := err.Error()
	if err == nil {
		return nil, fmt.Errorf("error is nil")
	}
	f := func(c rune) bool {
		return c == ',' || c == ':' || c == ' '
	}
	info := strings.FieldsFunc(strErr, f)
	if info[0] == "parameter" || info[0] == "session" {
		param, err := strconv.Atoi(info[1])
		if err != nil {
			return nil, fmt.Errorf("couldn't parse parameter error parameter")
		}
		if info[2] != "error" || info[3] != "code" {
			return nil, fmt.Errorf("couldn't parse parameter error code")
		}
		code := hex2int(info[4])
		paramErr.Parameter = tpm2.RCIndex(param)
		paramErr.Code = tpm2.RCFmt1(code)
		return &paramErr, nil
	}
	return nil, fmt.Errorf("couldn't parse error strings: %s", strErr)
}

func Detect(rwc io.ReadWriteCloser) (bool, error) {
	_ = tpm2.Startup(rwc, tpm2.StartupClear)
	session, _, err := tss.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionHMAC,
		tpm2.AlgXOR,
		tpm2.AlgSHA256)
	if err != nil {
		return false, err
	}
	defer tpm2.FlushContext(rwc, session)

	hnd, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tss.ECCPublicKey)
	if err != nil {
		return false, err
	}
	defer tpm2.FlushContext(rwc, hnd)
	// We don't test oobwrite because it's dangerous
	err = oobRead(rwc, tpm2.HandleEndorsement, session, nil)
	if err == nil {
		return false, fmt.Errorf("no tpm error returned")
	}
	paramErr, err := parserParameterError(err)
	if err != nil {
		return false, fmt.Errorf("couldn't parse parameter error %v", err)
	}
	if paramErr != nil && paramErr.Parameter == 1 {
		switch paramErr.Code {
		case 0x1a:
			return false, nil
		case 0x15:
			return true, nil
		}
	}
	return false, fmt.Errorf("unknown TPM session error")
}

func oobRead(rwc io.ReadWriteCloser, owner, sess tpmutil.Handle, payload []byte) error {
	auth := tpm2.AuthCommand{
		Session:    sess,
		Attributes: tpm2.AttrContinueSession | tpm2.AttrDecrypt,
		Auth:       []byte(""),
	}

	parent, err := tpmutil.Pack(owner)
	if err != nil {
		return err
	}
	encodedAuth, err := tss.EncodeAuthArea(auth)
	if err != nil {
		return err
	}
	cmd := tss.Concat(parent, encodedAuth, payload)

	_, err = tss.RunCommand(rwc, tpm2.TagSessions, tpm2.CmdCreatePrimary, tpmutil.RawBytes(cmd))
	return err
}
