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
