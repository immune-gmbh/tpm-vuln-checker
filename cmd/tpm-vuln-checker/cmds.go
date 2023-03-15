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

	"github.com/fatih/color"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cloud"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cve201715361"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cve20231017"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/tss"
	"github.com/manifoldco/promptui"
)

var (
	NonVulnerableStyle   = color.New(color.FgGreen, color.BgBlack, color.Bold).SprintFunc()
	VulnerableStyle      = color.New(color.FgRed, color.BgBlack, color.Bold).SprintFunc()
	MaybeVulnerableStyle = color.New(color.FgYellow, color.BgBlack, color.Bold).SprintFunc()
	InfoStyle            = color.New(color.FgBlue, color.BgBlack, color.Bold).SprintFunc()
)

type context struct {
	Emulator bool
}

type versionCmd struct {
}

type checkCmd struct {
	NonInteractive bool `flag optional name:"auto-upload" help:"Always uploads anonymized data without asking"`
}

func (v *versionCmd) Run(ctx *context) error {
	showVersion(programName, gittag, gitcommit)
	return nil
}

func (v *checkCmd) Run(ctx *context) error {
	socket, err := tss.NewTPM(ctx.Emulator)
	if err != nil {
		return err
	}
	defer socket.Close()
	if !tss.IsTPM2(socket) {
		return fmt.Errorf("no TPM 2.0 found")
	}
	tpmInfo, err := tss.ReadTPM2VendorAttributes(socket)
	if err != nil {
		return err
	}
	fmt.Printf("TPM Manufacturer: \t\t%s\nTPM Spec Revision: \t\t%s\nTPM Family: \t\t\t%s\n",
		tpmInfo.Manufacturer.String(), tpmInfo.SpecRevision.String(), tpmInfo.Family.String())
	fmt.Printf("\nStarting TPM vulnerabilities checks.. This may take few seconds!\n\n")
	vulnerable, cveData20231017, err := cve20231017.IsVulnerable(socket)
	if err != nil {
		if err.Error() == "unknown" {
			fmt.Printf("CVE 2023-1017/2023-1018: \t%s", MaybeVulnerableStyle("Probably Not Vulnerable"))
		} else {
			return err
		}
	} else {
		if vulnerable {
			fmt.Printf("CVE 2023-1017/2023-1018: \t%s\n", VulnerableStyle("Vulnerable"))
			fmt.Printf("%s", InfoStyle("Please apply the latest BIOS update to update the TPM firmware. OEMs/ODMs ship TPM updates as part of BIOS updates."))
		} else {
			fmt.Printf("CVE 2023-1017/2023-1018: \t%s", NonVulnerableStyle("Not Vulnerable"))
		}
	}
	fmt.Println()
	vulnerable, cveData201715361, err := cve201715361.IsVulnerable(socket)
	if err != nil {
		fmt.Printf("CVE 2017-15361: \t\t%s", MaybeVulnerableStyle("Check Error"))
	} else {
		if vulnerable {
			fmt.Printf("CVE 2017-15361: \t\t%s\n", VulnerableStyle("Vulnerable"))
		} else {
			fmt.Printf("CVE 2017-15361: \t\t%s", NonVulnerableStyle("Not Vulnerable"))
		}
	}
	fmt.Println()
	if v.NonInteractive {
		if err := cloud.UploadAnonData(tpmInfo, cveData20231017, cveData201715361); err != nil {
			return err
		}
	} else {
		prompt := promptui.Prompt{
			Label:     "Do you want to upload this data anonymized for analysis and tpm firmware update support",
			IsConfirm: true,
		}
		fmt.Println()
		_, err := prompt.Run()
		if err != nil {
			return nil
		}
		if err := cloud.UploadAnonData(tpmInfo, cveData20231017, cveData201715361); err != nil {
			return err
		}
	}
	return nil
}

var cli struct {
	Emulator bool       `help:"Enable emulator mode."`
	Version  versionCmd `cmd help:"Prints the version of the program"`
	Check    checkCmd   `short:"c" cmd help:"Check TPM for CVE 2023-1017-1018"`
}
