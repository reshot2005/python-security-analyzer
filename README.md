    # Python Security Analyzer — Offline Code Security / DevSecOps Tool

    [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
    [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
    [![Offline](https://img.shields.io/badge/mode-offline%20first-important.svg)](#)
    [![secintel](https://img.shields.io/badge/schema-secintel%20v1-purple.svg)](https://github.com/reshot2005/secintel-core)
    [![GitHub](https://img.shields.io/badge/github-reshot2005%2Fpython-security-analyzer-black.svg)](https://github.com/reshot2005/python-security-analyzer)

    > **Python SAST for secrets, eval/exec, and insecure deserialization — offline Python code security analyzer for DevSecOps pipelines.**

    **Category:** Code Security / DevSecOps  
    **Collection phase tool:** 1/10  
    **Schema:** [secintel-core](https://github.com/reshot2005/secintel-core) v1  
    **Repository:** https://github.com/reshot2005/python-security-analyzer  
    **Author account:** [reshot2005](https://github.com/reshot2005)

    ## Why Python Security Analyzer ranks for security search

    Python Security Analyzer is an **offline-first**, research-grade **code security / devsecops** utility designed for practitioners who need reproducible analysis without uploading sensitive artifacts to SaaS scanners. It emits structured findings through the shared **secintel** evidence taxonomy (OBSERVED / DERIVED / INFERRED / CORRELATED / VERIFIED) so results are auditable, exportable, and CI-friendly.

    ### Primary SEO keywords
    `Python SAST, Python security scanner, eval detection, deserialization security, Python secrets scan`

    ### Topics
    `devsecops` `application-security` `sast` `secure-coding` `cybersecurity` `code-security` `sbom` `security-tools` `python` `offline-security` `python-security` `ast`

    ## What problem does this solve?

    Statically analyze Python source for dangerous patterns: secrets, eval/exec, and insecure deserialization — fully offline.

    Offline focused Python SAST with evidence schema.

    ## Key features

    - AST-oriented Python scanning
- Secrets & dangerous API detection
- Insecure deserialization flags
- CI-friendly JSON/SARIF
- Local-only analysis

    ## Ideal use cases

    - Pre-commit Python security checks
- PR review assistance
- Legacy code audits

    ## Who should use this

    - Security engineers & AppSec / NetSec specialists
    - SOC / DFIR / malware analysts (as applicable)
    - Bug bounty hunters and penetration testers
    - DevSecOps teams needing offline/air-gapped tooling
    - Students and researchers learning code security / devsecops

    ## Quick start

    ```bash
    git clone https://github.com/reshot2005/python-security-analyzer.git
    cd python-security-analyzer
    python3.12 -m venv .venv
    source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
    pip install -e ../secintel-core  # or: pip install -e git+https://github.com/reshot2005/secintel-core.git#egg=secintel-core
    pip install -e ".[dev]"

    python-security-analyzer analyze sample_data --json
    python-security-analyzer analyze sample_data --html report.html
    python-security-analyzer version
    ```

    ### Exports for interoperability

    ```bash
    python-security-analyzer analyze sample_data \
      --json --html report.html --csv findings.csv --sarif results.sarif
    ```

    ## Evidence quality & reproducibility

    - Findings follow **secintel** classification rules (confidence only where schema allows).
    - Provenance includes tool version, config hash, and input integrity metadata.
    - Set `SECINTEL_SOURCE_DATE_EPOCH` for deterministic timestamps in CI.

    ```bash
    export SECINTEL_SOURCE_DATE_EPOCH=1704067200
    python-security-analyzer analyze sample_data --json
    ```

    ## Development

    ```bash
    ruff check src tests
    mypy src
    pytest
    ```

    ## Related tools in this collection

    Browse more offline security research tools by [reshot2005](https://github.com/reshot2005?tab=repositories): network security, web AppSec, DevSecOps, digital forensics, and static malware analysis — each in its own public repository with the same secintel reporting contract.

    ## License

    MIT — free for research, education, and commercial use with attribution preserved.

    ---

    ### Discoverability blurb (search engines & GitHub)

    **Python Security Analyzer (python-security-analyzer)** — Python SAST for secrets, eval/exec, and insecure deserialization — offline Python code security analyzer for DevSecOps pipelines. Search terms: Python SAST, Python security scanner, eval detection, deserialization security, Python secrets scan. Open-source, MIT-licensed, Python 3.12, offline cybersecurity tool by reshot2005.
