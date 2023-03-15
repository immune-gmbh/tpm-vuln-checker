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
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cve201715361"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/cve20231017"
	"github.com/immune-gmbh/tpm-vuln-checker/pkg/tss"
)

const (
	uploadURL = "https://upload.vuln.immune.gmbh"
)

type AnonInfo struct {
	Info             *tss.TPM20Info        `json:"info"`
	CVEData20231017  *cve20231017.CVEData  `json:"cveData-20231017"`
	CVEData201715361 *cve201715361.CVEData `json:"cveData-201715361"`
}

func UploadAnonData(info *tss.TPM20Info, cveData20231017 *cve20231017.CVEData, cveData201715361 *cve201715361.CVEData) error {
	if info == nil {
		return fmt.Errorf("tpm info is nil")
	}
	var payload AnonInfo
	payload.Info = info
	payload.CVEData20231017 = cveData20231017
	payload.CVEData201715361 = cveData201715361
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
