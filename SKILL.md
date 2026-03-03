---
name: ai-threat-analyzer
description: AI-powered security threat prediction and prevention system
version: 1.0.0
author: OpenClaw Security Team
tags: ["threat-modeling", "security", "ai", "predictive", "prevention"]
requires: ["python3.9+", "docker", "git", "openclaw-cli"]
dependencies:
  - name: transformers
    version: ">=4.30.0"
  - name: torch
    version: ">=2.0.0"
  - name: bandit
    version: ">=1.7.5"
  - name: semgrep
    version: ">=1.50.0"
  - name: trivy
    version: ">=0.45.0"
  - name: grype
    version: ">=0.75.0"
env_vars:
  - name: OPENCLAW_AI_MODEL
    default: "microsoft/codebert-base"
    description: "AI model for code analysis"
  - name: THREAT_SCAN_CONFIDENCE
    default: "0.7"
    description: "Minimum confidence threshold (0-1)"
  - name: OPENCLAW_AI_API_KEY
    description: "API key for remote AI model inference (optional)"
---

# AI Threat Analyzer Skill

## Purpose

AI Threat Analyzer predicts and prevents security vulnerabilities by analyzing code, dependencies, infrastructure-as-code, and configuration files using a hybrid approach combining static analysis, machine learning models, and threat intelligence.

**Real Use Cases:**
- Detect subtle injection vulnerabilities in Node.js/Python services that traditional tools miss
- Predict future security issues based on code complexity and developer patterns
- Identify supply chain risks in npm/PyPI dependencies before they're exploited
- Analyze Terraform/Kubernetes manifests for misconfigurations that could lead to data exposure
- Generate secure coding recommendations tailored to your stack (React, Django, FastAPI, etc.)
- Prioritize vulnerabilities based on AI-assessed exploit likelihood and business impact

## Scope

This skill provides the following commands:

### `openclaw skill ai-threat-analyzer scan-code [options] <path>`

Performs AI-enhanced static analysis on source code.

**Flags:**
- `--language=<lang>` - Target language: `python`, `javascript`, `go`, `java`, `all` (default: auto-detect)
- `--severity=<level>` - Minimum severity: `low`, `medium`, `high`, `critical` (default: `medium`)
- `--model=<path|huggingface>` - Custom model path or HuggingFace ID (default: env OPENCLAW_AI_MODEL)
- `--confidence=<0.0-1.0>` - AI confidence threshold (default: 0.7)
- `--context-lines=<n>` - Include N lines of context in reports (default: 5)
- `--exclude=<pattern>` - Exclude paths matching glob pattern (repeatable)
- `--output=<format>` - Output format: `json`, `sarif`, `html`, `terminal` (default: terminal)
- `--include-suppressed` - Include suppressed/false positive predictions

**Example:**
```bash
openclaw skill ai-threat-analyzer scan-code ./services/api --language python --severity medium --output sarif --context-lines 3
```

### `openclaw skill ai-threat-analyzer scan-deps [options] <manifest>`

Analyzes dependencies for known CVEs, supply chain risks, and suspicious patterns.

**Flags:**
- `--type=<type>` - Manifest type: `npm`, `pip`, `cargo`, `gomod`, `all` (default: auto)
- `--depth=<n>` - Dependency tree depth to analyze (default: 3, max: 10)
- `--include-dev` - Include devDependencies (default: false)
- `--check-license` - Flag restrictive licenses (default: true)
- `--taint-tracking` - Trace data flow from vulnerable deps to code (default: true)
- `--output=<format>` - `json`, `table`, `github-annotations`
- `--fix-pr` - Create PR with automated updates for vulnerable deps

**Example:**
```bash
openclaw skill ai-threat-analyzer scan-deps ./package.json --taint-tracking --output github-annotations
```

### `openclaw skill ai-threat-analyzer scan-infra [options] <path>`

Scans infrastructure-as-code for security misconfigurations.

**Flags:**
- `--iac-types=<list>` - Comma-separated: `terraform,kubernetes,cloudformation,docker,helm` (default: all)
- `--policy=<path>` - Custom OPA/Open Policy Agent policy bundle
- `--cloud-provider=<provider>` - Context for cloud-specific checks: `aws`, `gcp`, `azure`, `all`
- `-- simulate-attacks` - Generate attack scenarios based on misconfigurations (default: false)
- `--output=<format>` - `json`, `sarif`, `cli-table`

**Example:**
```bash
openclaw skill ai-threat-analyzer scan-infra ./infra --iac-types terraform,kubernetes --cloud-provider aws --simulate-attacks
```

### `openclaw skill ai-threat-analyzer predict-threat [options] <code-or-config>`

AI model predicts how a code change or configuration might be exploited in the next 90 days.

**Flags:**
- `--timeframe=<days>` - Prediction window: 30, 60, 90 days (default: 90)
- `--asset-type=<type>` - Asset classification: `public-facing`, `internal`, `pci`, `hipaa`, `generic`
-- `--patch-rush` - Accelerated prediction for emergency patches (reduced accuracy, faster)

**Example:**
```bash
openclaw skill ai-threat-analyzer predict-threat ./src/auth.py --asset-type public-facing
```

### `openclaw skill ai-threat-analyzer apply-fixes [options] <scan-result>`

Automatically applies AI-recommended fixes where confidence is >90%.

**Flags:**
- `--dry-run` - Show fixes without applying (default: false)
- `--max-fixes=<n>` - Maximum fixes to apply in one run (default: 10)
- `--require-approval` - Interactive approval per fix (default: true)
- `--backup-dir=<path>` - Create backups before modifications
- `--git-commit` - Create git commit for each applied fix
- `--pr` - Create pull request with all fixes instead of direct apply

**Example:**
```bash
openclaw skill ai-threat-analyzer apply-fixes ./scan-results.json --pr --require-approval --backup-dir ./backups
```

### `openclaw skill ai-threat-analyzer train-model [options] <dataset>`

Fine-tunes the AI model on your organization's historical vulnerability data.

**Flags:**
- `--base-model=<hf-id>` - Base HuggingFace model (default: microsoft/codebert-base)
- `--epochs=<n>` - Training epochs (default: 5)
- `--batch-size=<n>` - Training batch size (default: 16)
- `--validation-split=<float>` - Validation split ratio (default: 0.2)
- `--output-dir=<path>` - Where to save fine-tuned model (default: ./models/threat-analyzer)
- `--push-to-hub` - Push to HuggingFace Hub (requires AUTH_TOKEN)

**Example:**
```bash
openclaw skill ai-threat-analyzer train-model ./historical-vulns.jsonl --epochs 10 --output-dir ./models/custom-threat-analyzer --batch-size 32
```

### `openclaw skill ai-threat-analyzer explain-finding <finding-id>`

Provides detailed, context-aware explanation of a specific vulnerability with remediation steps.

**Flags:**
- `--format=<format>` - `text`, `markdown`, `json` (default: markdown)
- `--audience=<level>` - Tailor explanation: `developer`, `security-engineer`, `manager` (default: developer)
- `--include-code-samples` - Provide secure vs vulnerable code examples (default: true)

**Example:**
```bash
openclaw skill ai-threat-analyzer explain-finding SQLI-2024-12345 --audience developer --format markdown
```

## Detailed Work Process

### Standard vulnerability analysis workflow:

1. **Preparation**
   ```bash
   # Set confidence threshold for your risk appetite
   export THREAT_SCAN_CONFIDENCE=0.75
   
   # Point to custom model if available
   export OPENCLAW_AI_MODEL="./models/fine-tuned-threat-analyzer"
   ```

2. **Run multi-layer scan**
   ```bash
   # Parallel scan of code, dependencies, and infrastructure
   openclaw skill ai-threat-analyzer scan-code ./src --output json > code-scan.json &
   openclaw skill ai-threat-analyzer scan-deps ./package.json --output json > deps-scan.json &
   openclaw skill ai-threat-analyzer scan-infra ./infra --output json > infra-scan.json &
   
   wait
   
   # Combine results
   cat code-scan.json deps-scan.json infra-scan.json | jq -s 'add' > combined-threats.json
   ```

3. **Review predictions**
   ```bash
   # Get top 10 critical findings with AI explanations
   openclaw skill ai-threat-analyzer explain-finding --audience security-engineer --format json $(jq -r '.[] | select(.severity=="critical") | .id' combined-threats.json | head -10) > critical-explanations.json
   
   # Generate prioritized action plan
   openclaw skill ai-threat-analyzer predict-threat ./src --asset-type public-facing > threat-predictions.json
   ```

4. **Apply fixes with validation**
   ```bash
   # Create PR with fixes (review required)
   openclaw skill ai-threat-analyzer apply-fixes combined-threats.json --pr --require-approval --max-fixes 20 --backup-dir ./threat-fix-backups
   
   # After PR approval and merge, verify fixes
   # (re-run the scan to confirm issues resolved)
   ```

5. **Continuous improvement**
   ```bash
   # Fine-tune on false positives/negatives to improve accuracy
   # Export reviewed findings to training dataset
   jq '[.[] | select(.reviewed==true)]' threat-reviews.jsonl > training-data.jsonl
   
   # Retrain model monthly
   openclaw skill ai-threat-analyzer train-model ./training-data.jsonl --epochs 3 --output-dir ./models/monthly-$(date +%Y%m)
   ```

### CI/CD Integration Example:

```yaml
# .github/workflows/threat-scan.yml
name: AI Threat Scan
on:
  pull_request:
    paths:
      - '**.py'
      - '**.js'
      - '**.tf'
      - 'package.json'
      - 'requirements.txt'

jobs:
  threat-analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install OpenClaw
        run: curl -sSL https://openclaw.io/install.sh | bash
      - name: AI Threat Scan
        run: |
          openclaw skill ai-threat-analyzer scan-code . --output sarif > threats.sarif
          openclaw skill ai-threat-analyzer scan-deps . --output sarif >> threats.sarif
          openclaw skill ai-threat-analyzer scan-infra ./infra --output sarif >> threats.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: threats.sarif
      - name: Fail on Critical
        run: |
          if jq -e '.[] | select(.severity=="critical" and (.confidence // 1) > 0.8)' threats.sarif > /dev/null; then
            echo "Critical threats detected!"
            exit 1
          fi
```

## Golden Rules

1. **Confidence Thresholds**
   - Only automatically apply fixes with >90% AI confidence
   - Manual review required for Medium+ severity findings with 70-90% confidence
   - Low confidence (<70%) findings must be manually validated before any action

2. **Data Privacy**
   - Never send proprietary code to external AI APIs without explicit permission
   - Prefer local model inference with `--model="./local-model"`
   - If using remote APIs, ensure data is anonymized and transmission is TLS-encrypted
   - Configure `OPENCLAW_AI_API_KEY` with limited-scope tokens only

3. **Change Management**
   - Never use `--dry-run false` (i.e., actual changes) without backups
   - Always run `--backup-dir` when applying fixes
   - Limit auto-fixes to 20 per run to prevent unintended mass changes
   - Require human approval for any fix that touches authentication, authorization, or encryption code

4. **Model Management**
   - Version your fine-tuned models with semantic versioning
   - Keep baseline model immutable; create new fine-tuned versions instead of overwriting
   - Test fine-tuned models on a validation set before production deployment
   - Archive all training datasets with scan results for reproducibility

5. **False Positive Handling**
   - Mark false positives with `--include-suppressed` flag to re-train model
   - Do NOT suppress findings without adding them to training feedback loop
   - Track false positive rate per model; retrain if rate exceeds 15%

6. **Supply Chain Security**
   - Always include `--taint-tracking` for dependency scans
   - Never use `--include-dev` in production builds without explicit security approval
   - Block any dependency flagged with `malicious` or `typosquatting` automatically

## Examples

### Example 1: Detecting a subtle SQL injection in Django

**Command:**
```bash
openclaw skill ai-threat-analyzer scan-code ./django-app --language python --severity medium --output json
```

**Input code (django-app/views.py):**
```python
def search_users(request):
    query = request.GET.get('q', '')
    # Vulnerable: raw SQL with string formatting
    User.objects.raw(f"SELECT * FROM users WHERE name = '{query}'")
```

**Output:**
```json
{
  "scan_id": "scan-2024-03-15-threat-001",
  "findings": [
    {
      "id": "SQLI-2024-12345",
      "severity": "high",
      "confidence": 0.92,
      "type": "SQL Injection",
      "file": "django-app/views.py",
      "line": 5,
      "code_snippet": "User.objects.raw(f\"SELECT * FROM users WHERE name = '{query}'\")",
      "ai_explanation": "The query parameter 'query' is directly interpolated into raw SQL without parameterization. Attackers can inject SQL via URL parameter 'q'. Unlike basic tools that detect raw SQL, our AI recognizes Django's ORM raw() method as high-risk when combined with f-strings. Exploitation likely within 30 days for public-facing apps.",
      "cwe": "CWE-89",
      "owasp": "A03:2021 – Injection",
      "fix_suggestion": "Use parameterized queries: User.objects.raw('SELECT * FROM users WHERE name = %s', [query])",
      "exploitability_score": 8.5,
      "impact_score": 9.0,
      "priority": "P1"
    }
  ]
}
```

**Verification:**
```bash
# Confirm finding exists with expected severity
jq '.findings[] | select(.id=="SQLI-2024-12345")' scan-results.json
# Should return finding with confidence >= 0.9
```

**Rollback:**
```bash
# If fix was applied and causes issues:
git checkout HEAD -- django-app/views.py
# Or restore from backup if backup-dir was used:
cp ./backups/views.py.bak ./django-app/views.py
```

### Example 2: Dependency supply chain risk detection

**Command:**
```bash
openclaw skill ai-threat-analyzer scan-deps ./package.json --taint-tracking --output json
```

**Input (package.json):**
```json
{
  "dependencies": {
    "lodash": "4.17.15",
    "pyodide": "0.23.4"
  }
}
```

**Output:**
```json
{
  "findings": [
    {
      "id": "DEP-2024-67890",
      "severity": "critical",
      "confidence": 0.88,
      "type": "Prototype Pollution",
      "dependency": "lodash@4.17.15",
      "cve": "CVE-2019-10744",
      "ai_analysis": "lodash versions <4.17.21 contain prototype pollution in merge() and set(). Your version (4.17.15) is vulnerable. AI flagged this because your codebase uses _.merge() in src/utils/js/deepMerge.js (line 12), creating an exploitable path.",
      "taint_path": [
        "package.json:lodash@4.17.15",
        "src/utils/js/deepMerge.js:12:_.merge(config, defaults)",
        "User-controlled input flows into merge() from HTTP request body"
      ],
      "fix": "Update to lodash@4.17.21 or replace with native Object.assign()",
      "affected_services": ["frontend", "admin-panel"],
      "priority": "P0"
    },
    {
      "id": "DEP-2024-67891",
      "severity": "medium",
      "confidence": 0.76,
      "type": "Suspicious Package",
      "dependency": "pyodide@0.23.4",
      "ai_analysis": "Pyodide downloads and executes Python packages at runtime. AI model identifies this as unusual for a web frontend, potentially introducing unvetted Python packages that could execute malicious code.",
      "recommendation": "Audit all pyodide.loadPackage() calls; consider vendoring required Python packages",
      "priority": "P2"
    }
  ]
}
```

**Fix application:**
```bash
# Create PR with automated dependency updates and required code changes
openclaw skill ai-threat-analyzer apply-fixes ./dep-scan.json --pr --require-approval --git-commit
```

**Verification:**
```bash
# After PR merge, verify vulnerable deps removed
npm list lodash | grep -q "4.17.21" || echo "lodash not updated!"
```

**Rollback:**
```bash
# If updated lodash breaks compatibility, revert to previous version
npm install lodash@4.17.15
# Revert PR changes:
git revert <merge-commit>
```

### Example 3: Infrastructure misconfiguration in Terraform

**Command:**
```bash
openclaw skill ai-threat-analyzer scan-infra ./terraform --iac-types terraform --cloud-provider aws --output json
```

**Input (terraform/main.tf):**
```hcl
resource "aws_s3_bucket" "public_data" {
  bucket_prefix = "public-data-"
  acl           = "public-read"
}

resource "aws_security_group" "web_sg" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Output:**
```json
{
  "findings": [
    {
      "id": "INFRA-2024-11111",
      "severity": "high",
      "confidence": 0.95,
      "type": "Overly Permissive S3 ACL",
      "resource": "aws_s3_bucket.public_data",
      "ai_explanation": "S3 bucket 'public-data-*' has ACL 'public-read'. AI model recognizes this as data exposure risk, especially for buckets containing user data. Combined with bucket_prefix predictability, this vulnerable to unauthorized data access.",
      "attack_scenario": "Attacker guesses bucket name via common naming pattern, reads all objects publicly, extracts PII.",
      "fix": "Remove 'acl' and use aws_s3_bucket_policy with explicit grants. Enable server-side encryption by default.",
      "priority": "P1"
    },
    {
      "id": "INFRA-2024-11112",
      "severity": "critical",
      "confidence": 0.98,
      "type": "Unrestricted Security Group",
      "resource": "aws_security_group.web_sg",
      "ai_explanation": "Security group allows ALL ports (0-65535) from ANY source (0.0.0.0/0). This exposes entire application stack to internet scanning and exploitation. AI flags this as immediate breach risk.",
      "attack_scenario": "Port scan reveals open database port (5432), attacker connects directly to PostgreSQL without authentication filtering.",
      "fix": "Restrict ingress to specific ports (80, 443) from known CIDR. Use separate security groups for app, DB, and internal services.",
      "priority": "P0"
    }
  ]
}
```

**Verification:**
```bash
# Check that terraform plan doesn't create vulnerable S3 buckets
terraform plan | grep -q "public-read" && echo "Vulnerable config still present!" || echo "S3 config secure"
```

**Rollback:**
```bash
# If fix introduced breaking changes, revert terraform state
terraform apply -var="revert_acl=vulnerable"  # Or manually revert .tf files and re-apply
```

### Example 4: Predicting future threats from code complexity

**Command:**
```bash
openclaw skill ai-threat-analyzer predict-threat ./src/auth --asset-type public-facing --timeframe 90
```

**Output:**
```json
{
  "prediction_id": "pred-2024-03-15-0001",
  "asset": "./src/auth (public-facing)",
  "target_date": "2024-06-13",
  "threats": [
    {
      "type": "Authentication Bypass",
      "likelihood": 0.73,
      "reasoning": "AI model detected high cyclomatic complexity (28) in authenticate() function with multiple early returns. Historical patterns show auth bypasses emerge 60-90 days after complexity exceeds 25.",
      "recommended_action": "Refactor authenticate() into smaller functions with explicit state machine. Add property-based testing with Hypothesis.",
      "potential_impact": "Complete system compromise"
    },
    {
      "type": "JWT Algorithm Confusion",
      "likelihood": 0.41,
      "reasoning": "Code uses pyjwt without explicit algorithm verification (line 89: jwt.decode(token)). Combined with RSA/ECDSA usage elsewhere, algorithm confusion attack possible.",
      "recommended_action": "Enforce algorithm: jwt.decode(token, key=public_key, algorithms=['RS256'])",
      "potential_impact": "Privilege escalation to any user"
    }
  ]
}
```

**Verification:**
```bash
# Check complexity baseline before refactoring
radon cc ./src/auth/authenticate.py -a | grep -q "Complexity: 28"
```

**Rollback:**
```bash
# If refactoring breaks auth flow, revert from git
git log --oneline -- src/auth/authenticate.py | head -5
git revert <commit-before-refactor>
```

### Example 5: Training a custom model on organization's vulnerability data

**Dataset (historical-vulns.jsonl):**
```json
{"code":"cursor.execute(\"SELECT * FROM users WHERE id=\"+user_id)","language":"python","vulnerable":true,"cwe":"CWE-89"}
{"code":"query = \"SELECT * FROM posts WHERE author='\"+author+\"'\"","language":"python","vulnerable":true,"cwe":"CWE-89"}
{"code":"cursor.execute(\"INSERT INTO logs(message)VALUES(?)\",(message,))","language":"python","vulnerable":false,"cwe":null}
```

**Command:**
```bash
openclaw skill ai-threat-analyzer train-model ./historical-vulns.jsonl --epochs 10 --output-dir ./models/company-threat-analyzer --batch-size 32 --validation-split 0.2
```

**Output:**
```text
[Training Output]
Epoch 1/10: loss=0.342, accuracy=0.765
Epoch 2/10: loss=0.218, accuracy=0.842
...
Epoch 10/10: loss=0.045, accuracy=0.987

Validation Results:
- Precision: 0.94
- Recall: 0.91
- F1-Score: 0.925

Model saved to: ./models/company-threat-analyzer
✓ Fine-tuned model exceeds baseline by +4.2% F1 on organization's data
```

**Verification:**
```bash
# Test fine-tuned model on holdout set
openclaw skill ai-threat-analyzer scan-code ./test-suite --model ./models/company-threat-analyzer --output json | jq '.findings | length'
# Should detect >90% of planted vulnerabilities
```

**Rollback:**
```bash
# Revert to baseline model
export OPENCLAW_AI_MODEL="microsoft/codebert-base"
# Or delete custom model
rm -rf ./models/company-threat-analyzer
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCLAW_AI_MODEL` | No | `microsoft/codebert-base` | Model identifier (local path or HuggingFace ID) |
| `THREAT_SCAN_CONFIDENCE` | No | `0.7` | Minimum confidence threshold (0.0-1.0) |
| `OPENCLAW_AI_API_KEY` | Conditionally | - | Required for remote model API (e.g., OpenAI, Anthropic, custom endpoint) |
| `OPENCLAW_AI_API_ENDPOINT` | Conditionally | - | Custom API endpoint if not using default HuggingFace |
| `THREAT_SCAN_MAX_TOKENS` | No | `4096` | Maximum tokens for AI model input |
| `THREAT_SCAN_BATCH_SIZE` | No | `16` | Batch size for model inference |

**Example .env file:**
```bash
OPENCLAW_AI_MODEL="./models/custom-analyzer-v2.1"
THREAT_SCAN_CONFIDENCE=0.8
OPENCLAW_AI_API_KEY="hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
THREAT_SCAN_MAX_TOKENS=2048
```

## Dependencies and Requirements

**System Requirements:**
- Python 3.9+ with pip
- Docker (for containerized scan environments)
- Git (for PR creation and backup management)
- 8GB RAM minimum, 16GB recommended for AI inference
- 10GB disk space for models and datasets

**Python Packages (installed automatically):**
```
transformers>=4.30.0
torch>=2.0.0
sentencepiece
accelerate
bandit>=1.7.5
semgrep>=1.50.0
trivy>=0.45.0
grype>=0.75.0
jq (CLI tool)
sarif-tools (CLI tool)
```

**Optional Dependencies:**
- `radon` - for code complexity analysis
- `safety` - Python dependency vulnerability DB
- `npm-audit` or `yarn-audit` - JavaScript vulnerability scanners
- `checkov` - additional infrastructure-as-code scanner
- `gitleaks` - secret detection

**One-time Setup:**
```bash
# Install system dependencies
sudo apt-get update && sudo apt-get install -y jq docker.io git

# Install OpenClaw skill dependencies (auto-handled by skill)
openclaw skill ai-threat-analyzer install-deps

# Download AI model (if not using remote API)
openclaw skill ai-threat-analyzer download-model microsoft/codebert-base
```

## Troubleshooting

### "CUDA out of memory" during scan
**Symptoms:** Process killed with CUDA error during AI analysis
**Solution:**
```bash
# Reduce batch size
export THREAT_SCAN_BATCH_SIZE=4
# Use CPU instead of GPU
export CUDA_VISIBLE_DEVICES=""  
# Or add flag: --device=cpu
```

### "Model not found" error
**Symptoms:** `OSError: Model name '...' was not found`
**Solution:**
```bash
# Ensure model exists locally or is correct HuggingFace ID
huggingface-cli login  # If accessing private model
openclaw skill ai-threat-analyzer download-model <correct-model-id>
# For local model: --model=./relative/path/to/model
```

### False positive flood on codebase
**Symptoms:** Hundreds of low-confidence warnings overwhelming signal
**Solution:**
```bash
# Raise confidence threshold
export THREAT_SCAN_CONFIDENCE=0.85
# Add specific exclusions
openclaw skill ai-threat-analyzer scan-code ./src --exclude '**/tests/**' --exclude '**/migrations/**'
# Build suppression list from false positives and retrain
openclaw skill ai-threat-analyzer train-model ./false-positives.jsonl --base-model=./models/current --epochs=1
```

### Docker not running (for isolated scan environments)
**Symptoms:** `docker: command not found` or `Cannot connect to the Docker daemon`
**Solution:**
```bash
# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker
# Add user to docker group (then re-login)
sudo usermod -aG docker $USER
```

### Dependency scan missing CVEs
**Symptoms:** No vulnerabilities found, but `npm audit` shows known issues
**Solution:**
```bash
# Ensure vulnerability DB is updated
trivy image --update
grype db update
# Re-scan with deeper depth
openclaw skill ai-threat-analyzer scan-deps ./package.json --depth 10
```

### PR creation fails (GitHub)
**Symptoms:** `gh: command not found` or authentication errors
**Solution:**
```bash
# Install GitHub CLI
sudo apt-get install gh
gh auth login  # Follow OAuth flow
# Ensure repository permissions allow PR creation
gh repo view
# Use SSH instead of HTTPS if needed
git remote set-url origin git@github.com:org/repo.git
```

### Slow scans on large codebases
**Symptoms:** Scans taking >1 hour for moderate-sized projects
**Solution:**
```bash
# Run scans in parallel with make or GNU parallel
find . -name "*.py" -type f | parallel "openclaw skill ai-threat-analyzer explain-finding {}" &
wait
# Cache model between runs (automatic on first load)
# Use --exclude to skip vendor/third-party code
openclaw skill ai-threat-analyzer scan-code . --exclude '**/node_modules/**' --exclude '**/.venv/**'
```

### "API rate limit exceeded" (remote AI)
**Symptoms:** HTTP 429 from `api.openai.com` or similar
**Solution:**
```bash
# Switch to local model for bulk scans
export OPENCLAW_AI_MODEL="./models/local-model"
# Or request quota increase on your AI provider
# Implement exponential backoff:
export THREAT_SCAN_RETRIES=3
export THREAT_SCAN_RETRY_DELAY=5
```

```