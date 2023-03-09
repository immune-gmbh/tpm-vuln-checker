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

	"github.com/alecthomas/kong"
)

const (
	programName = "tpm-vuln-checker"
	programDesc = "Checks for TPM vulnerabilities in Linux and Windows userland"
)

var (
	gitcommit string
	gittag    string
)

func showVersion(toolName, tag, commit string) {
	fmt.Printf("%s %s\n", toolName, tag)
	fmt.Println("")
	fmt.Printf("Build Commit: %s\n", commit)
	fmt.Println("License: Apache License, Version 2.0")
	fmt.Println("")
	fmt.Println("https://immune.gmbh")
	fmt.Println("Copyright (c) 2023, immune GmbH.")
	fmt.Println("All rights reserved.")
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name(programName),
		kong.Description(programDesc),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))
	err := ctx.Run(&context{Emulator: cli.Emulator})
	fmt.Println()
	ctx.FatalIfErrorf(err)
}
