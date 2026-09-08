// Checkpoint J3: local OWASP pipeline gate only.
// Do not call credentials() here — missing IDs fail the job before the scan.
// Microsoft/cloud agents and this laptop are different computers (same as GitHub G2).
// Engine-from-Jenkins is Checkpoint J4 in docs/CI.md.
pipeline {
    agent any
    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
        stage('Install Athena CLI') {
            steps {
                sh '''
                python3 -m pip install --upgrade pip
                python3 -m pip install .
                athena version
                '''
            }
        }
        stage('SAST Scan') {
            steps {
                // Scan logic lives in the CLI. Plugins only exec it.
                sh '''
                set +e
                MODES="pipeline"
                EXTRA=""
                # J4: bind ATHENA_API_URL / ATHENA_API_KEY on the job, then set REPO_URL.
                if [ -n "${ATHENA_API_URL:-}" ] && [ -n "${REPO_URL:-}" ]; then
                  MODES="code-review,secrets,iac,sca,pipeline"
                  EXTRA="--repo ${REPO_URL} --branch ${BRANCH_NAME:-main}"
                fi
                athena scan \
                  --target . \
                  --modes "${MODES}" \
                  --format sarif --output athena-results.sarif \
                  --json-output athena-results.json \
                  --fail-on high --quiet $EXTRA
                SCAN_EXIT=$?
                athena scan --target . --local . --format junit --output athena-results.xml --fail-on high --quiet || true
                exit $SCAN_EXIT
                '''
            }
        }
    }
    post {
        always {
            // CICD-SEC-10: always publish for audit trail
            junit allowEmptyResults: true, testResults: 'athena-results.xml'
            archiveArtifacts artifacts: 'athena-results.sarif,athena-results.json,athena-results.xml',
                             allowEmptyArchive: true
        }
    }
}
