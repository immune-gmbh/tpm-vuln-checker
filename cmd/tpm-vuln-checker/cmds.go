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
package main

import (
	"fmt"
	"io"
	"net/url"

	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cve"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/tss"
)

const (
	swtpmURL = "tcp://127.0.0.1:2321"
)

type context struct {
	Emulator bool
}

type versionCmd struct {
}

type checkCmd struct {
}

func (v *versionCmd) Run(ctx *context) error {
	showVersion(programName, gittag, gitcommit)
	return nil
}

func (v *checkCmd) Run(ctx *context) error {
	var err error
	var rwc io.ReadWriteCloser
	if ctx.Emulator {
		var url *url.URL
		url, err = url.Parse(swtpmURL)
		if err != nil {
			return err
		}
		rwc, err = tss.OpenNetTPM(url)
		if err != nil {
			return err
		}
	} else {
		rwc, err = tss.OpenTPM()
		if err != nil {
			return err
		}
	}
	defer rwc.Close()
	found, err := cve.Detect(rwc)
	if err != nil {
		return err
	}
	tpmInfo, err := tss.ReadTPM2VendorAttributes(rwc)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n%s\n%s\n", tpmInfo.Manufacturer.String(), tpmInfo.SpecRevision, tpmInfo.Family)
	if found {
		fmt.Println("found")
	} else {
		fmt.Println("Not found")
	}
	return nil
}

var cli struct {
	Emulator bool       `help:"Enable emulator mode."`
	Version  versionCmd `cmd help:"Prints the version of the program"`
	Check    checkCmd   `short:"c" cmd help:"Check TPM for CVE2023-1017-1018"`
}
