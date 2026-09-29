pipeline {
    agent any

    options {
        disableConcurrentBuilds(abortPrevious: false)
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '20'))
    }

    parameters {
        booleanParam(
            name: 'ALERTS_ENABLED',
            defaultValue: true,
            description: 'Включить временные Telegram alerts через credentials Everyday Test'
        )
        string(
            name: 'EXPECTED_PROXY_IP',
            defaultValue: '185.128.214.128',
            description: 'Ожидаемый внешний IP dedicated proxy'
        )
        string(
            name: 'HTTP_TIMEOUT_SECONDS',
            defaultValue: '10',
            description: 'Timeout HTTP-проверки'
        )
        string(
            name: 'REDIRECT_MAX_HOPS',
            defaultValue: '10',
            description: 'Максимальная длина redirect-цепочки'
        )
    }

    environment {
        PYTHONUNBUFFERED = '1'
        PYTHON_BIN = 'python3'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install dependencies') {
            steps {
                sh '''
                    set -eu
                    rm -rf allure-results
                    mkdir -p allure-results
                    "$PYTHON_BIN" -m venv .venv
                    .venv/bin/python -m pip install --upgrade pip
                    .venv/bin/pip install -r requirements.txt
                    .venv/bin/pip install --upgrade certifi
                    .venv/bin/python -c 'import certifi; print("CA bundle:", certifi.where())'
                '''
            }
        }

        stage('Unit tests') {
            steps {
                sh '''
                    set -eu
                    PYTHONPATH=. .venv/bin/pytest -q
                '''
            }
        }

        stage('Run secret landings monitor') {
            steps {
                withCredentials([
                    file(credentialsId: 'secret-landings-urls', variable: 'URLS_FILE'),
                    string(credentialsId: 'Proxy_for_secret_lend', variable: 'PROXY_URL'),
                    string(credentialsId: 'telegram_proxy_url', variable: 'TELEGRAM_PROXY_URL'),
                    string(credentialsId: 'telegram_proxy_auth_secret', variable: 'TELEGRAM_PROXY_AUTH_SECRET'),
                    string(credentialsId: 'tg_proxy_creds_survarius', variable: 'TELEGRAM_PROXY_CREDS')
                ]) {
                    withEnv([
                        "ALERTS_ENABLED=${params.ALERTS_ENABLED}",
                        "TELEGRAM_PROXY_TIMEOUT_SEC=15"
                    ]) {
                        sh '''
                            set -eu
                            rm -rf allure-results
                            mkdir -p /var/lib/jenkins/secret_lends_check
                            .venv/bin/python monitor.py \\
                              --urls-file "$URLS_FILE" \\
                              --proxy-url "$PROXY_URL" \\
                              --expected-ip "$EXPECTED_PROXY_IP" \\
                              --allure-dir allure-results \\
                              --timeout "$HTTP_TIMEOUT_SECONDS" \\
                              --max-redirects "$REDIRECT_MAX_HOPS" \\
                              --preflight-attempts 3 \\
                              --alert-state-file /var/lib/jenkins/secret_lends_check/alert_state.json
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                def hasAllureResults = sh(
                    script: "find allure-results -type f -name '*-result.json' | grep -q .",
                    returnStatus: true
                ) == 0
                if (hasAllureResults) {
                    archiveArtifacts artifacts: 'allure-results/**', allowEmptyArchive: false, fingerprint: true
                    allure includeProperties: false, jdk: '', results: [[path: 'allure-results']]
                } else {
                    echo 'Allure results are absent; report publication skipped.'
                }
            }
        }
    }
}
