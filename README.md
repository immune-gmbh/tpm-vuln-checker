# TPM 2.0 Vulnerability Scanning Tool
This is a tool written in Golang designed to scan for multiple TPM vulnerabilities using the Immune Security tpm-vuln-checker library.

## Requirements
To use this tool, you will need the following:

* TPM device driver
* Windows Vista+ or Linux operating system

## Installation
Download the latest release of the tpm-vuln-checker library from the following link: [Releases](https://github.com/immune-gmbh/tpm-vuln-checker/releases/latest
)

### Run the checker

```
tpm-vuln-checker check
```

### Upload anonymized TPM data to a custom URL
We aggregate data from the TPM to evaluate TPM 2.0 metrics when you use the tool --upload
If you want to use the data on your own you can define a custom upload url. The tool will do a HTTP POST with multipart form data containing a json.
The filename send in the POST is a random UUID with a .json ending.

```
tpm-vuln-checker --url=https://your.domain check --upload
```

## Vulnerabilities Detected
This tool is designed to detect the following vulnerabilities using the tpm-vuln-checker library:

* ***TPM ROCA vulnerability:*** 
Resources: https://www.ncsc.gov.uk/guidance/roca-infineon-tpm-and-secure-element-rsa-vulnerability-guidance

* ***TPM read/write OOB vulnerability:***
https://blog.quarkslab.com/vulnerabilities-in-the-tpm-20-reference-implementation-code.html

## Disclaimer
The author of this tool is not responsible for any damages or liabilities that may arise from the use of this tool.

This tool may upload anonymized data to a server for metrics analysis purposes. This data is used to improve the tool and identify potential vulnerabilities in TPMs. No personally identifiable information is collected or stored. By using this tool, you consent to the collection and use of anonymized data for metrics analysis purposes. If you do not consent to this, do not use this tool.
