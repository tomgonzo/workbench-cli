# FossID Workbench CLI (Experimental)
A prototype CLI inspired by the official [Workbench Agent](https://github.com/fossid-ab/workbench-cli) that interacts with the Workbench API to:

### Project and Scan Management
* Create Projects and Scans for first-time scans
* Reuse Projects and Scans for incremental scans

### Scanning Options
*   Upload directories or files for scanning.
*   Pull Git repositories (branches or tags) for scanning.
*   Import Dependency Analysis results (e.g., `analyzer-result.json`) from FossID-DA or ORT.
*   Import SPDX or CycloneDX SBOMs as Workbench Scans - with built-in validation.

### Results Options
*   Fetch scan results (scan metrics, components, licenses, dependencies, policy violations, vulnerabilities) and save as JSON.
*   Fail CI/CD pipelines based on the presence of pending identifications, policy violations, or vulnerabilities.
*   Generate and download reports (scan or project scope) to consume or save as build artifacts.

# Usage
Run `workbench-cli` with the desired command and its options.

```bash
workbench-cli <COMMAND> [OPTIONS...]
```

### Commands:
* scan: Upload local code files or directories for scanning. 
* scan-git: Clone a Git branch, tag, or commit to scan it.
* import-da: Import Dependency Analysis results into a Scan. (from FossID-DA or ORT)
* import-sbom: Import a SPDX or CycloneDX SBOM as a Scan.
* show-results: Fetch and display results for an existing scan.
* evaluate-gates: Check pending IDs, policy violations, and vulnerabilities.
* download-reports: download reports for a scan or project.

Use `workbench-cli --help` to see the main help message and `workbench-cli <COMMAND> --help` for help on a specific command.

## Configuration
Credentials for the Workbench API can be provided via environment variables for convenience:

*   `WORKBENCH_URL`: API Endpoint URL (e.g., `https://workbench.example.com/api.php`)
*   `WORKBENCH_USER`: Workbench Username
*   `WORKBENCH_TOKEN`: Workbench API Token

Note: You can also provide these using the `--api-url`, `--api-user`, and `--api-token` arguments, which override the environment variables if set.

## Running with Docker:
This repo publishes a public image to GHCR. Run it with:
`docker run ghcr.io/tomgonzo/workbench-cli:latest --help`

## Running with Python
Prefer to run without Docker? You'll need at least Python 3.9 installed.

1.  **Clone the Repository:**
    ```bash
    git clone github.com/tomgonzo/workbench-cli
    cd workbench-cli
    ```

2.  **Create and Activate a Virtual Environment (Recommended):**
    Using a virtual environment isolates the tool's dependencies from your global Python installation.

    *   **Create:**
        ```bash
        python3 -m venv .venv
        ```
    *   **Activate:**
        *   macOS / Linux:
            ```bash
            source .venv/bin/activate
            ```
        *   Windows (Git Bash/WSL):
            ```bash
            source .venv/Scripts/activate
            ```
        *   Windows (Command Prompt/PowerShell):
            ```bash
            .\.venv\Scripts\activate
            ```
        You should see `(.venv)` appear at the beginning of your terminal prompt.

3.  **Install the Package:**
    Install `workbench-cli` and its dependencies into your virtual environment.

    ```bash
    pip install .
    ```
    
This makes the `workbench-cli` command available in your terminal while the virtual environment is active.

# Examples:
(Ensure environment variables are set or use --api-url, --api-user, --api-token)

## Examples for SCAN command
Scan takes a Project Name, Scan Name, and Path. It also supports various `show-*` arguments for showing results after the scan is done.

The scan command supports three modes of operation:
* KB Scan Only (default)
* Dependency Analysis Only (using `--dependency-analysis-only`)
* KB Scan + Dependency Analysis (using `--run-dependency-analysis`)

#### Scan by uploading a directory, running Dependency Analysis. After the scan, show Scan Metrics, Identified Components, and Licenses.
```bash
workbench-cli scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --run-dependency-analysis \
    --show-components --show-licenses --show-scan-metrics
```

#### Skip KB Scan and run only Dependency Analysis on uploaded code
```bash
workbench-cli scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --dependency-analysis-only \
    --show-dependencies --show-vulnerabilities
```

Note: When a directory is passed, it will be compressed as ZIP before uploading.

#### Scan a ZIP file, reusing identifications from a specific project. After the scan, show Dependencies, Policy Warnings, and Vulnerabilities.
```bash
workbench-cli scan \
    --project-name MYPROJ --scan-name MYSCAN02 \
    --path ./src.zip \
    --id-reuse --id-reuse-type project --id-reuse-source "MyBaseProject" \
    --show-dependencies --show-policy-warnings --show-vulnerabilities
```

## Examples for SCAN-GIT Command
Scan-Git takes a Project Name, Scan Name, Git Repo URL, and either a Branch, Tag, or Commit Ref. It also supports various `show-*` arguments for showing results after the scan is done. 

Like the scan command, scan-git supports three modes of operation:
* KB Scan Only (default)
* Dependency Analysis Only (using `--dependency-analysis-only`)
* KB Scan + Dependency Analysis (using `--run-dependency-analysis`)

#### Scan by Cloning a Branch from a Git repository. After the scan, show Scan Metrics, Policy Warnings, and Vulnerabilities.
```bash
workbench-cli scan-git \
    --project-name MYGITPROJ --scan-name MYGITSCAN01 \
    --git-url https://github.com/owner/repo --git-branch develop \
    --show-scan-metrics --show-policy-warnings --show-vulnerabilities
```

#### Skip KB Scan and run only Dependency Analysis on cloned Git repository
```bash
workbench-cli scan-git \
    --project-name MYGITPROJ --scan-name MYGITSCAN02 \
    --git-url https://github.com/owner/repo --git-branch main \
    --dependency-analysis-only \
    --show-dependencies --show-vulnerabilities
```

#### Scan by Cloning a Tag from a Git repository:
```bash
workbench-cli scan-git \
    --project-name MYGITPROJ --scan-name GitTag1.0 \
    --git-url https://github.com/owner/repo --git-tag "1.0" \
    --show-dependencies --show-vulnerabilities
```

#### Scan by Cloning a Commit from a Git repository:
```bash
workbench-cli scan-git \
    --project-name MYGITPROJ --scan-name Commit-ffac537e6cbbf934b08745a378932722df287a53 \
    --git-url https://github.com/owner/repo --git-commit ffac537e6cbbf934b08745a378932722df287a53 \
    --show-policy-warnings
```

## Examples for IMPORT-DA Command
Import-DA takes a Project Name, Scan Name, and Path to a `analyzer-result.json` file. This works with FossID-DA or ORT's Analyzer.

#### Import an Analyzer JSON from ORT or FossID-DA (does not scan)
```bash
workbench-cli import-da \
    --project-name MYPROJ --scan-name MYSCAN03 \
    --path ./ort-test-data/analyzer-result.json \
    --show-dependencies --show-vulnerabilities
```

## Examples for IMPORT-SBOM Command
Import-SBOM takes a Project Name, Scan Name, and a path to a SPDX or CycloneDX SBOM. It also supports various `show-*` arguments for showing results after the scan is done. 

#### Import a SPDX SBOM and show Vulnerabilities
```bash
workbench-cli import-sbom \
    --project-name MYPROJ --scan-name MYSCAN03 \
    --path ./tests/fixtures/spdx-document.rdf \
    --show-vulnerabilities
```

#### Import a CycloneDX SBOM and show Policy Warnings
```bash
workbench-cli import-sbom \
    --project-name ApplicationName --scan-name SupplierBOM \
    --path ./tests/fixtures/cyclonedx-bom.json \
    --show-policy-warnings
```

## Examples for SHOW-RESULTS Command
Show-Results takes a Project Name, Scan Name, and any of the various `show-*` arguments. The results can be exported as JSON and saved to the path specified with the `--results-path` argument.

#### Show All Available Results
```bash
workbench-cli show-results \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-scan-metrics --show-licenses --show-components --show-dependencies --show-scan-metrics --show-vulnerabilities \
    --results-path ./results.json
```

## Examples for the EVALUATE-GATES Command
Evaluate-Gates takes a Project Name and Scan Name. To fail a Pipeline, specify one or more of the available `--fail-on-*` arguments. This command exits with code 0 if gates pass, 1 if they fail.

#### Evaluate Gates, failing if there are Files Pending ID and showing Pending Files:
```bash
workbench-cli evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-pending-files --fail-on-pending
```

#### Evaluate Gates, failing if Policy Warnings or Files Pending ID are present:
```bash
workbench-cli evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --fail-on-policy --fail-on-pending
```

#### Evaluate Gates, failing if CRITICAL severity vulnerabilities are present:
```bash
workbench-cli evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --fail-on-vuln-severity critical
```

Note: `--fail-on-vuln-severity` accepts critical, high, medium, or low. It will fail on vulnerabilities of the specified severity or higher.

## Examples for DOWNLOAD-REPORTS Command
Download-Reports takes a Project Name, Scan Name, Report Scope, and Report Path. By default, all available reports are downloaded. Choose which reports to download by adjusting the `--report-scope` and `--report-type`. 

#### Download Project-Level XLSX and SPDX reports:
```bash
workbench-cli download-reports \
    --project-name MYPROJ --report-scope project \
    --report-type xlsx,spdx --report-save-path reports/
```

#### Download all Scan-Level reports:
```bash
workbench-cli download-reports \
    --project-name MYPROJ --report-scope scan \
    --report-save-path reports/
```

## Logging
The CLI creates a log file named workbench-cli-log.txt in the directory where it's run. You can control the logging level using the --log argument (DEBUG, INFO, WARNING, ERROR). Console output is generally kept at INFO level unless --log is set higher.
