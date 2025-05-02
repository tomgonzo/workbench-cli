# FossID Workbench Agent (Experimental)
A prototype CLI inspired by the official [Workbench Agent](https://github.com/fossid-ab/workbench-agent) that interacts with the Workbench API to:

### Project and Scan Management
* Create Projects and Scans for first-time scans
* Reuse Projects and Scans for incremental scans

### Scanning Options
*   Upload directories or files for scanning.
*   Pull Git repositories (branches or tags) for scanning.
*   Import Dependency Analysis results (e.g., `analyzer-result.json`) from FossID-DA or ORT.

### Results Options
*   Fetch scan results (scan metrics, components, licenses, dependencies, policy violations, vulnerabilities) and save as JSON.
*   Fail CI/CD pipelines based on the presence of pending identifications, policy violations, or vulnerabilities.
*   Generate and download reports (scan or project scope) to consume or save as build artifacts.

## Prerequisites

*   **Python 3.9+** and **pip**
*   Access to FossID Workbench

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone github.com/fossid-ab/workbench-agent
    cd workbench-agent
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
    Install `workbench-agent` and its dependencies into your virtual environment.

    ```bash
    pip install .
    ```
    *(You might need to use `pip3` instead of `pip` depending on your system configuration).*

    This makes the `workbench-agent` command available in your terminal while the virtual environment is active.

4.  **(Optional) Installation for Development:**
    If you plan to modify the agent's code, install it in "editable" mode. This links the installed command to your source code, so changes are reflected immediately without reinstalling.

    ```bash
    pip install -e .
    ```

## Configuration

Credentials for the Workbench API can be provided via environment variables for convenience and security:

*   `WORKBENCH_URL`: API Endpoint URL (e.g., `https://workbench.example.com/api.php`)
*   `WORKBENCH_USER`: Workbench Username
*   `WORKBENCH_TOKEN`: Workbench API Token

You can also provide these using the `--api-url`, `--api-user`, and `--api-token` command-line arguments, which will override the environment variables if set.

## Usage

Run `workbench-agent` with the desired command and its options.

```bash
workbench-agent <COMMAND> [OPTIONS...]
```

Use `workbench-agent --help` to see the main help message and workbench-agent <COMMAND> --help for help on a specific command.

## Commands:

* scan: Upload local code files or directories for scanning. 
* scan-git: Clone a Git branch or tag to scan it.
* import-da: Import Dependency Analysis results. (from FossID-DA or ORT)
* show-results: Fetch and display results for an existing scan.
* evaluate-gates: Check pending IDs, policy violations, and vulnerabilities.
* download-reports: download reports for a scan or project.

## Examples:

(Ensure environment variables are set or use --api-url, --api-user, --api-token)

### Full scan uploading a directory, run DA, show results:

```bash
workbench-agent scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --run-dependency-analysis \
    --show-components --show-licenses --show-scan-metrics
```

### Scan using identification reuse from a specific project:

```bash
workbench-agent scan \
    --project-name MYPROJ --scan-name MYSCAN02 \
    --path ./src.zip \
    --id-reuse --id-reuse-type project --id-reuse-source "MyBaseProject" \
    --show-scan-metrics --show-components --show-licenses --show-dependencies
```

### Import DA results (does not scan)

```bash
workbench-agent import-da \
    --project-name MYPROJ --scan-name MYSCAN03 \
    --path ./ort-test-data/analyzer-result.json \
    --show-dependencies
```

### Show results for an existing scan:

```bash
workbench-agent show-results \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-scan-metrics --show-licenses --show-components --show-dependencies --show-scan-metrics --show-vulnerabilities \
    --results-path ./results.json
```

### Evaluate gates for a scan (check pending IDs, show pending files, fail on pending IDs):

```bash
workbench-agent evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-files --fail-on-pending
```

### Evaluate gates for a scan (fail on vuln severity):

```bash
workbench-agent evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --fail-on-vuln-severity critical
```

(This command exits with code 0 if gates pass, 1 if they fail)


### Scan a Git repository branch:

```bash
workbench-agent scan-git \
    --project-name MYGITPROJ --scan-name MYGITSCAN01 \
    --git-url https://github.com/owner/repo.git --git-branch develop
```

### Download XLSX and SPDX reports for a project:

```bash
workbench-agent download-reports \
    --project-name MYPROJ --report-scope project \
    --report-type xlsx,spdx --report-save-path reports/
```

## Logging
The agent creates a log file named log-agent.txt in the directory where it's run. You can control the logging level using the --log argument (DEBUG, INFO, WARNING, ERROR). Console output is generally kept at INFO level unless --log is set higher.
