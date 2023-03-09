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
package cloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/google/uuid"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cve"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/tss"
)

const (
	uploadURL = "https://upload.vuln.immune.gmbh"
)

type AnonInfo struct {
	Info       *tss.TPM20Info `json:"info"`
	Vulnerable bool           `json:"vulnerable"`
	Raw        *cve.CVEData   `json:"cvedata"`
}

func UploadAnonData(info *tss.TPM20Info, raw *cve.CVEData, vuln bool) error {
	if info == nil {
		return fmt.Errorf("tpm info is nil")
	}
	var payload AnonInfo
	payload.Info = info
	payload.Vulnerable = vuln
	payload.Raw = raw
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	id := uuid.New().String()
	part, _ := writer.CreateFormFile("file", id+".json")
	io.Copy(part, bytes.NewReader(data))
	writer.Close()
	request, err := http.NewRequest("POST", uploadURL, body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("http status code %d, body: %v", response.StatusCode, response.Body)
	}
	return nil
}
