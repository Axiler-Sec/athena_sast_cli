// Checkpoint J3: local OWASP pipeline gate only.
// Do not call credentials() here — missing IDs fail the job before the scan.
// Microsoft/cloud agents and this laptop are different computers (same as GitHub G2).
// Engine-from-Jenkins: add credentials only when the agent can reach the engine over HTTPS.
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
                set +x
                python3 -m pip install --upgrade pip
                python3 -m pip install .
                athena version
                '''
            }
        }
        stage('Monitor') {
            steps {
                // Record first, never fail on findings. Exit 2 still fails the job.
                sh '''
                set +x
                athena monitor --target . --modes pipeline --quiet
                '''
            }
        }
        stage('SAST Scan') {
            steps {
                // Scan logic lives in the CLI. Plugins only exec it. This stage is the gate.
                // QA: never add set -x — ATHENA_API_KEY would land in the console log.
                sh '''
                set +x
                set +e
                SCAN_EXIT=0
                if [ -n "${ATHENA_API_URL:-}" ] && [ -n "${REPO_URL:-}" ]; then
                  athena scan \
                    --target . \
                    --modes code-review,secrets,iac,sca,pipeline \
                    --format sarif --output athena-results.sarif \
                    --json-output athena-results.json \
                    --fail-on high --quiet \
                    --repo "${REPO_URL}" --branch "${BRANCH_NAME:-main}"
                  SCAN_EXIT=$?
                else
                  athena scan \
                    --target . \
                    --modes pipeline \
                    --format sarif --output athena-results.sarif \
                    --json-output athena-results.json \
                    --fail-on high --quiet
                  SCAN_EXIT=$?
                fi
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
