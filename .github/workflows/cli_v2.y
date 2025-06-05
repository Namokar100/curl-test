name: CBOM Vulnerability Analysis with CLI_v2

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

env:
  CODEQL_VERSION: v2.21.2
  CODEQL_DIR: ${{ github.workspace }}/codeql
  CBOM_TOOL_DIR: ${{ github.workspace }}/.cbom-tool
  ANALYSIS_OUTPUT_DIR: ${{ github.workspace }}/analysis-results

jobs:
  cbom-analysis:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Current Repository
      uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.10'

    - name: Install Essential Build Tools
      run: |
        sudo apt-get update -y
        sudo apt-get install -y --no-install-recommends \
          python3-dev python3-venv git curl build-essential

    - name: Install build dependencies
      run: |
        sudo apt-get install -y build-essential autoconf automake libtool pkg-config cmake clang gcc g++ make
        sudo apt-get install -y libssl-dev zlib1g-dev libnghttp2-dev
        sudo apt-get install -y libpsl-dev libidn2-dev libssh2-1-dev
        sudo apt-get install -y libkrb5-dev librtmp-dev libldap2-dev
        sudo apt-get install -y libgnutls28-dev libcurl4-openssl-dev

    - name: Setup CodeQL CLI
      run: |
        mkdir -p $HOME/codeql-cli
        wget -q https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.21.3/codeql-bundle-linux64.tar.gz -O codeql-bundle.tar.gz
        tar -xzf codeql-bundle.tar.gz -C $HOME/codeql-cli
        CODEQL_PATH=$(find $HOME/codeql-cli -name codeql -type f | head -n 1)
        CODEQL_DIR=$(dirname "$CODEQL_PATH")
        echo "CODEQL_PATH=${CODEQL_PATH}" >> $GITHUB_ENV
        echo "CODEQL_DIR=${CODEQL_DIR}" >> $GITHUB_ENV
        echo "${CODEQL_DIR}" >> $GITHUB_PATH
        "${CODEQL_PATH}" --version

    - name: Clone CBOM Analysis Tool
      uses: actions/checkout@v4
      with:
        repository: Namokar100/tool
        path: ${{ env.CBOM_TOOL_DIR }}
        token: ${{ secrets.PAT_TOKEN }}

    - name: Install CBOM Tool Dependencies
      run: |
        cd ${{ env.CBOM_TOOL_DIR }}
        python -m pip install --upgrade pip setuptools wheel
        python -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
        pip install -e .

    - name: Create Analysis Directory
      run: |
        mkdir -p ${{ env.ANALYSIS_OUTPUT_DIR }}

    - name: Run CBOM Analysis
      run: |
        cd ${{ env.CBOM_TOOL_DIR }}
        source venv/bin/activate
        
        # Get absolute path of repository to analyze
        REPO_PATH="${{ github.workspace }}"
        
        # Use the FastAPI rules file for consistency
        RULES_PATH="${{ env.CBOM_TOOL_DIR }}/data/default_rules.yaml"
        
        # Run the CLI analysis
        python calyptra_ql/cli.py \
          "${REPO_PATH}" \
          --build-command "autoreconf -fi && ./configure --with-openssl && make -j$(nproc)" \
          -o "${{ env.ANALYSIS_OUTPUT_DIR }}/cbom.json" \
          -c "${{ env.ANALYSIS_OUTPUT_DIR }}/compliance_report.txt" \
          --rules "${RULES_PATH}" \
          -vv

    - name: Check for Vulnerabilities
      id: check-vulnerabilities
      run: |
        REPORT_PATH="analysis-results/compliance_report.txt"
    
        if [ ! -f "$REPORT_PATH" ]; then
          echo "::error::Compliance report not found"
          exit 1
        fi
    
        # Extract each violation block
        VIOLATION_BLOCKS=$(awk '/^- Rule ID:/ {found=1; print; next} found && NF==0 {found=0; print "---"} found && NF > 0 {print}' "$REPORT_PATH")
    
        # Count violations (based on "- Rule ID:" lines)
        VIOLATIONS_COUNT=$(echo "$VIOLATION_BLOCKS" | grep -c '^- Rule ID:')
    
        if [ "$VIOLATIONS_COUNT" -gt 0 ]; then
          echo "has_vulnerabilities=true" >> $GITHUB_ENV
          echo "::warning::Security vulnerabilities were found in the analysis"
          echo "Found $VIOLATIONS_COUNT violations in the analysis"
    
          echo "Violation Details:"
          echo "$VIOLATION_BLOCKS" | awk '
            /^- Rule ID:/ { rule=$0; next }
            /^  Location:/ {
              split($2, pathline, ":");
              file=pathline[1]; line=pathline[2];
              sub(/^- Rule ID: */, "", rule);
              printf "- Rule: %s, File: %s, Line: %s\n", rule, file, line
            }
          '
        else
          echo "has_vulnerabilities=false" >> $GITHUB_ENV
          echo "No security vulnerabilities found"
        fi

    - name: Upload Analysis Results
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: cbom-analysis-results
        path: |
          ${{ env.ANALYSIS_OUTPUT_DIR }}/cbom.json
          ${{ env.ANALYSIS_OUTPUT_DIR }}/compliance_report.txt
        retention-days: 7

    - name: Create Analysis Summary
      if: always()
      run: |
        cd ${{ github.workspace }}
        JSON_PATH="analysis-results/cbom.json"
        
        echo "## CBOM Analysis Results" >> $GITHUB_STEP_SUMMARY
        echo "Analysis completed at: $(date)" >> $GITHUB_STEP_SUMMARY
        echo "### Repository Analyzed" >> $GITHUB_STEP_SUMMARY
        echo "Repository: ${{ github.repository }}" >> $GITHUB_STEP_SUMMARY
        echo "Branch: ${GITHUB_REF#refs/heads/}" >> $GITHUB_STEP_SUMMARY
        echo "Commit: ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
        echo "" >> $GITHUB_STEP_SUMMARY
        
        if [ ! -f "$JSON_PATH" ]; then
          echo "### CBOM JSON report not found." >> $GITHUB_STEP_SUMMARY
          exit 1
        fi
        
        # Install jq if not available
        if ! command -v jq &> /dev/null; then
          sudo apt-get update -y && sudo apt-get install -y jq
        fi
        
        # Extract crypto assets from JSON
        TOTAL_VIOLATIONS=$(jq '.crypto_assets | length' "$JSON_PATH")
        
        echo "### Security Violations Found" >> $GITHUB_STEP_SUMMARY
        echo "**Total violations found: $TOTAL_VIOLATIONS**" >> $GITHUB_STEP_SUMMARY
        echo "" >> $GITHUB_STEP_SUMMARY
        
        if [ "$TOTAL_VIOLATIONS" -gt 0 ]; then
          # Group violations by rule/identifier for severity mapping
          jq -r '.crypto_assets[] | "\(.filePath):\(.lineNumber):\(.identifier)"' "$JSON_PATH" | while IFS=':' read -r file line identifier; do
            # Map identifiers to severity (you can customize this mapping)
            case "$identifier" in
              "DES_ecb_encrypt"|"DES_cbc_encrypt") 
                severity="High"
                rule="DEPRECATED_DES"
                description="Use of $identifier function detected. DES is deprecated, prefer AES."
                ;;
              "MD5_Init"|"MD5_Update"|"MD5_Final")
                severity="Medium"
                rule="DEPRECATED_MD5"
                description="Use of $identifier function detected. MD5 is cryptographically weak."
                ;;
              "SHA1_Init"|"SHA1_Update"|"SHA1_Final")
                severity="Medium"
                rule="DEPRECATED_SHA1"
                description="Use of $identifier function detected. SHA1 is cryptographically weak."
                ;;
              "RC4_set_key"|"RC4")
                severity="High"
                rule="DEPRECATED_RC4"
                description="Use of $identifier function detected. RC4 is insecure."
                ;;
              *)
                severity="Medium"
                rule="CRYPTO_FUNCTION"
                description="Cryptographic function $identifier detected."
                ;;
            esac
            
            echo "#### Violation in \`$file\` at line $line" >> $GITHUB_STEP_SUMMARY
            echo "**Rule**: $rule" >> $GITHUB_STEP_SUMMARY
            echo "**Severity**: $severity" >> $GITHUB_STEP_SUMMARY
            echo "**Description**: $description" >> $GITHUB_STEP_SUMMARY
            echo "" >> $GITHUB_STEP_SUMMARY
            
            # Show code context if file exists
            if [ -f "$file" ]; then
              echo "**Affected Code:**" >> $GITHUB_STEP_SUMMARY
              echo '```c' >> $GITHUB_STEP_SUMMARY
              
              # Show 3 lines before and after
              start_line=$((line - 3))
              end_line=$((line + 3))
              if [ $start_line -lt 1 ]; then start_line=1; fi
              
              awk -v start="$start_line" -v end="$end_line" -v target="$line" '
                NR >= start && NR <= end {
                  if (NR == target) {
                    printf "→ %d: %s\n", NR, $0
                  } else {
                    printf "  %d: %s\n", NR, $0
                  }
                }
              ' "$file" >> $GITHUB_STEP_SUMMARY
              
              echo '```' >> $GITHUB_STEP_SUMMARY
            else
              echo "File not found in workspace." >> $GITHUB_STEP_SUMMARY
            fi
            echo "" >> $GITHUB_STEP_SUMMARY
          done
          
          # Create violation statistics
          echo "### Violation Statistics" >> $GITHUB_STEP_SUMMARY
          echo "**Total violations**: $TOTAL_VIOLATIONS" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          
          # Count by severity (simplified mapping)
          HIGH_COUNT=$(jq -r '.crypto_assets[] | select(.identifier | test("DES_|RC4")) | .identifier' "$JSON_PATH" | wc -l)
          MEDIUM_COUNT=$((TOTAL_VIOLATIONS - HIGH_COUNT))
          
          echo "**By severity:**" >> $GITHUB_STEP_SUMMARY
          if [ $HIGH_COUNT -gt 0 ]; then
            echo "- High: $HIGH_COUNT" >> $GITHUB_STEP_SUMMARY
          fi
          if [ $MEDIUM_COUNT -gt 0 ]; then
            echo "- Medium: $MEDIUM_COUNT" >> $GITHUB_STEP_SUMMARY
          fi
          echo "" >> $GITHUB_STEP_SUMMARY
        else
          echo "No violations found." >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
        fi
        
        echo "### Full Reports" >> $GITHUB_STEP_SUMMARY
        echo "Detailed reports are available in the workflow artifacts:" >> $GITHUB_STEP_SUMMARY
        echo "- CBOM Report (cbom.json)" >> $GITHUB_STEP_SUMMARY
        echo "- Compliance Report (compliance_report.txt)" >> $GITHUB_STEP_SUMMARY
        echo "" >> $GITHUB_STEP_SUMMARY
        echo "**Job summary generated at run-time**" >> $GITHUB_STEP_SUMMARY

    - name: Fail if Vulnerabilities Found
      if: env.has_vulnerabilities == 'true'
      run: |
        echo "Security vulnerabilities were found in the analysis"
        exit 1
