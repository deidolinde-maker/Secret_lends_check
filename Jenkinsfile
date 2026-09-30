pipeline {
    agent any

    options {
        disableConcurrentBuilds(abortPrevious: false)
        timestamps()
        buildDiscarder(logRotator(daysToKeepStr: '30', artifactDaysToKeepStr: '7'))
    }

    parameters {
        booleanParam(
            name: 'ALERTS_ENABLED',
            defaultValue: true,
            description: 'Включить Telegram alerts через credentials Big Landing Test'
        )
        booleanParam(
            name: 'CHAIN_NEXT_RUN',
            defaultValue: true,
            description: 'После завершения ставить следующий прогон через 10 минут'
        )
        string(
            name: 'TARGET_SITE',
            defaultValue: '',
            description: 'Проверить только этот site из JSON; пусто — все сайты'
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
        PIP_CACHE_DIR = '/var/lib/jenkins/secret_lends_check/pip-cache'
        SHEETS_REPORT_URL = 'https://docs.google.com/spreadsheets/d/13domluVIULqjjGPBqcrFPCjf0V-4_55Li3-qnTItAGQ/edit?usp=sharing'
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
                    mkdir -p "$PIP_CACHE_DIR"
                    "$PYTHON_BIN" -m venv .venv
                    .venv/bin/python -m pip install --cache-dir "$PIP_CACHE_DIR" --upgrade pip
                    .venv/bin/pip install --cache-dir "$PIP_CACHE_DIR" -r requirements.txt
                    .venv/bin/pip install --cache-dir "$PIP_CACHE_DIR" --upgrade certifi
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

        stage('TLS CA diagnostics') {
            steps {
                withCredentials([
                    string(credentialsId: 'Proxy_for_secret_lend', variable: 'PROXY_URL')
                ]) {
                    sh '''
                        set -eu
                        .venv/bin/python -c '
import os
from pathlib import Path

import certifi
import requests

url = "https://t2-internet.online/"
proxies = {"http": os.environ["PROXY_URL"], "https": os.environ["PROXY_URL"]}
checks = [("certifi", certifi.where()), ("system", "/etc/ssl/certs/ca-certificates.crt")]

for name, bundle in checks:
    if not Path(bundle).exists():
        print(f"TLS {name}: NOT_AVAILABLE path={bundle}")
        continue
    client = requests.Session()
    client.trust_env = False
    try:
        response = client.get(url, proxies=proxies, verify=bundle, timeout=20)
        print(f"TLS {name}: PASS status={response.status_code} bundle={bundle}")
    except requests.RequestException as exc:
        print(f"TLS {name}: FAIL {type(exc).__name__}: {exc}")
    finally:
        client.close()
'
                        .venv/bin/python tls_certificate_diagnostic.py
                    '''
                }
            }
        }

        stage('Run secret landings monitor') {
            steps {
                withCredentials([
                    file(credentialsId: 'secret-landings-urls', variable: 'URLS_FILE'),
                    string(credentialsId: 'Proxy_for_secret_lend', variable: 'PROXY_URL'),
                    string(credentialsId: 'telegram_proxy_url', variable: 'TELEGRAM_PROXY_URL'),
                    string(credentialsId: 'telegram_proxy_auth_secret', variable: 'TELEGRAM_PROXY_AUTH_SECRET'),
                    string(credentialsId: 'telegram_proxy_global_test', variable: 'TELEGRAM_PROXY_CREDS'),
                    string(credentialsId: 'google-sheets-webhook-url', variable: 'SHEETS_WEBHOOK_URL'),
                    string(credentialsId: 'google-sheets-webhook-token', variable: 'SHEETS_WEBHOOK_TOKEN')
                ]) {
                    withEnv([
                        "ALERTS_ENABLED=${params.ALERTS_ENABLED}",
                        "TELEGRAM_PROXY_TIMEOUT_SEC=15",
                        "TARGET_SITE=${params.TARGET_SITE ?: ''}"
                    ]) {
                        sh '''
                            set -eu
                            target_site="${TARGET_SITE-}"
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
                              --site "$target_site" \\
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
                if (params.CHAIN_NEXT_RUN) {
                    build job: env.JOB_NAME,
                        wait: false,
                        quietPeriod: 600,
                        parameters: [
                            booleanParam(name: 'ALERTS_ENABLED', value: params.ALERTS_ENABLED),
                            booleanParam(name: 'CHAIN_NEXT_RUN', value: params.CHAIN_NEXT_RUN),
                            string(name: 'TARGET_SITE', value: params.TARGET_SITE ?: ''),
                            string(name: 'EXPECTED_PROXY_IP', value: params.EXPECTED_PROXY_IP),
                            string(name: 'HTTP_TIMEOUT_SECONDS', value: params.HTTP_TIMEOUT_SECONDS),
                            string(name: 'REDIRECT_MAX_HOPS', value: params.REDIRECT_MAX_HOPS)
                        ]
                }
            }
        }
    }
}
