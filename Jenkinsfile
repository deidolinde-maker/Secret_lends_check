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
                    "$PYTHON_BIN" -m venv .venv
                    .venv/bin/python -m pip install --upgrade pip
                    .venv/bin/pip install -r requirements.txt
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
                    string(credentialsId: 'telegram_proxy_global_test', variable: 'TELEGRAM_PROXY_CREDS')
                ]) {
                    withEnv([
                        "ALERTS_ENABLED=${params.ALERTS_ENABLED}",
                        "TELEGRAM_PROXY_TIMEOUT_SEC=15"
                    ]) {
                        sh '''
                            set -eu
                            rm -rf allure-results
                            .venv/bin/python monitor.py \\
                              --urls-file "$URLS_FILE" \\
                              --proxy-url "$PROXY_URL" \\
                              --expected-ip "$EXPECTED_PROXY_IP" \\
                              --allure-dir allure-results \\
                              --timeout "$HTTP_TIMEOUT_SECONDS" \\
                              --max-redirects "$REDIRECT_MAX_HOPS" \\
                              --preflight-attempts 3
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'allure-results/**', allowEmptyArchive: true, fingerprint: true
            script {
                if (fileExists('allure-results')) {
                    allure includeProperties: false, jdk: '', results: [[path: 'allure-results']]
                }
            }
        }
    }
}
