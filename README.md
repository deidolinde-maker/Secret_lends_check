# Secret_lends_check

Мониторинг доступности лендингов из Jenkins Secret File `secret-landings-urls`.

Jenkins Credential для dedicated proxy: `Proxy_for_secret_lend`. Значение proxy не хранится в репозитории и передаётся только через credentials binding.

## Первый запуск

```powershell
python monitor.py `
  --urls-file secret_landings_urls.json `
  --proxy-url http://user:password@proxy.example:8080 `
  --expected-ip 203.0.113.10 `
  --allure-dir allure-results
```

До проверки URL выполняется proxy preflight. При трёх неудачных попытках прогон останавливается с сообщением `Ошибка подключения прокси, прогон остановлен`; прямой fallback отсутствует.

Без `--proxy-url` монитор отказывается запускаться. Локальные `HTTP_PROXY`, `HTTPS_PROXY` и `NO_PROXY` не используются: маршрут задаётся только явным dedicated proxy из Jenkins.

## Временные алерты

Для включения Telegram alerts в Jenkins задать:

```text
ALERTS_ENABLED=true
TELEGRAM_PROXY_URL=<credential binding>
TELEGRAM_PROXY_AUTH_SECRET=<credential binding>
TELEGRAM_PROXY_CREDS=<Big Landing Test credential binding>
```

При ошибке отправляется alert по сайту и типу ошибки. Повторяющиеся ошибки напоминаются по существующей схеме, recovery отправляется после восстановления. Саммари всего прогона отправляется в чат после запусков в 09:00 и 17:00 по Москве; отправка подтверждается Telegram proxy и не дублируется для одного слота. Локально alerts выключены по умолчанию.

Ошибки обрабатываются по сайту сразу после завершения его страниц, не после завершения всего списка. Между прогонами хранится только state серий: повторяющаяся ошибка одного сайта агрегируется на notification steps 1/4/12 и далее по 24-часовому правилу.

Если TLS-проверка не проходит, запись получает `error_type=SSL` и `availability=FAILED`. HTTP-код, полученный диагностическим повтором с отключённой проверкой сертификата, помечается как `DIAGNOSTIC_ONLY` и не считается успешной доступностью страницы.

`secret_landings_urls.json` не хранится в репозитории. Он передаётся в job как Jenkins Secret File.

## Jenkins Pipeline

Job должна быть Pipeline job с `Pipeline script from SCM` и веткой `main`. Jenkinsfile использует credentials:

```text
secret-landings-urls
Proxy_for_secret_lend
telegram_proxy_url          # proxy endpoint
telegram_proxy_auth_secret  # proxy auth secret
telegram_proxy_global_test  # Big Landing Test
```

Для публикации Allure в Jenkins должен быть установлен Allure Jenkins plugin. Если plugin ещё не установлен, build всё равно сохранит `allure-results` как artifact, но шаг публикации потребуется включить после установки plugin.

## Проверки

```powershell
pytest -q
```
