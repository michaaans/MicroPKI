# MicroPKI

Минималистичный инструмент для создания инфраструктуры открытых ключей (PKI) в учебных целях.

## Зависимости

- Python 3.10+
- OpenSSL
- cryptography >= 46.0.0
- pytest >= 7.0

## Установка

```bash
# Клонируйте репозиторий
git clone https://github.com/michaaans/MicroPKI.git
cd MicroPKI

# Создайте виртуальное окружение
python3 -m venv venv

# Активируйте (linux)
source venv/bin/activate

# Установите проект в режиме разработки
pip install -e .

# или

# Установите проект в режиме разработки ВМЕСТЕ С pytest
pip install -e ".[test]"
```

```bash
# Запуск модульных тестов

pytest

# или

pytest tests/ -v
```

## Использование

Создание парольных фраз
```bash
# Инициализация парольной фразы для корневого УЦ
echo -n "MySecure_Passphrase_RootCA" > secrets/ca.pass

# Инициализация парольной фразы для промежуточного УЦ
echo -n "MySecure_Passphrase_IntermediateCA" > secrets/intermediate.pass
```

Инициализация БД
```bash
micropki db init --db-path ./pki/micropki.db
# Вывод: База данных инициализирована: pki\micropki.db

# миграция при изменении таблиц

micropki db init
# Вывод: Миграция схемы: версия 1 → 2...
#         Миграция на версию 2 завершена (добавлена таблица crl_metadata)
```

Инициализация корневого CA (RSA-4096)
```bash
micropki ca init \
    --subject "/CN=Demo Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki \
    --validity-days 3650
```

Инициализация корневого CA (ECC P-384)
```bash
micropki ca init \
    --subject "CN=ECC Root CA,O=MicroPKI" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki
```

Создание промежуточного CA
```bash
micropki ca issue-intermediate \
    --root-cert pki/certs/ca.cert.pem \
    --root-key pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/intermediate.pass \
    --out-dir pki \
    --validity-days 1825 \
    --pathlen 0
```

Выпуск серверного сертификата
```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MicroPKI" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir pki/certs \
    --validity-days 365
    
# или с записью в БД

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com, O=MicroPKI" \
    --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 \
    --db-path pki/micropki.db
```

Выпуск клиентского сертификата
```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir pki/certs
    
# или с записью в БД

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --db-path pki/micropki.db
```

Выпуск сертификата подписи кода
```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir pki/certs
    
# или с записью в БД

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --db-path pki/micropki.db
```

Просмотр сертификатов
```bash
# Список всех
micropki ca list-certs

# Только действительные
micropki ca list-certs --status valid

# В формате (table/json/csv)
micropki ca list-certs --format json

# Конкретный сертификат
micropki ca show-cert 69C41A28D533E208
```

Отзыв сертификата
```bash
# Посмотреть список сертификатов чтобы найти серийный номер
micropki ca list-certs

# Отозвать с подтверждением
micropki ca revoke 69C41A28D533E208 --reason keyCompromise

# Отозвать без подтверждения
micropki ca revoke 69C41A28D533E208 --reason superseded --force
```

**Допустимые причины отзыва:**
`unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`,
`superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`,
`privilegeWithdrawn`, `aACompromise`

Генерация CRL
```bash
# CRL промежуточного CA
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass

# CRL корневого CA
micropki ca gen-crl \
    --ca root \
    --ca-cert pki/certs/ca.cert.pem \
    --ca-key pki/private/ca.key.pem \
    --ca-pass-file secrets/root.pass

# С указанием срока nextUpdate
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --next-update 14
```

Получение CRL через HTTP
```bash
# Запуск сервера в фоне или отдельном терминале
micropki repo serve

# В другом терминале (cmd):
curl http://localhost:8080/crl --output ca.crl.pem

# С указанием параметра
curl http://localhost:8080/crl?ca=root --output root.crl.pem

# или

curl http://localhost:8080/crl?ca=intermediate --output intermediate.crl.pem
```

HTTP-сервер
```bash
# Запуск
micropki repo serve

# или 

micropki repo serve --host 127.0.0.1 --port 8080

# В другом терминале:

# Получить корневой CA
curl http://localhost:8080/ca/root

# Получить промежуточный CA
curl http://localhost:8080/ca/intermediate

# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/69C41A28D533E208

# CRL
curl http://localhost:8080/crl
curl http://localhost:8080/crl?ca=root
curl http://localhost:8080/crl?ca=intermediate

# Некорректный серийный номер
curl http://localhost:8080/certificate/XYZ
```

OCSP-Responder
```bash
# Создать цепочку CA в локальной папке (для проверки openssl)
cat ./pki/certs/intermediate.cert.pem ./pki/certs/ca.cert.pem > ./pki/certs/ca-chain.pem
```

Выпуск сертификата OCSP-ответчика
```bash
micropki ca issue-ocsp-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db
```

Проверка сертификата OCSP-ответчика
```bash
openssl x509 -in pki/certs/OCSP_Responder.cert.pem -text -noout

# В выводе должны присутствовать:
# X509v3 Basic Constraints: critical
#     CA:FALSE
# X509v3 Key Usage: critical
#     Digital Signature
# X509v3 Extended Key Usage:
#     OCSP Signing
```

Запуск OCSP-ответчика
```bash
# В отдельном терминале или в фоне
micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path pki/micropki.db \
    --responder-cert pki/certs/OCSP_Responder.cert.pem \
    --responder-key pki/certs/OCSP_Responder.key.pem \
    --ca-cert pki/certs/intermediate.cert.pem \
    --cache-ttl 120
```

Проверка работоспособности:
```bash
curl http://127.0.0.1:8081/health
# Ожидается: {"status":"ok","service":"MicroPKI OCSP Responder"}
```

Выпустить тестовый сертификат
```bash
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=test.example.com" \
    --san dns:test.example.com \
    --out-dir pki/certs \
    --db-path pki/micropki.db
```

Запросить статус — ожидается good
```bash
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/test.example.com.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem

#Ожидаемый вывод:
#OCSP Response Status: successful (0x0)
#Cert Status: good
#Response verify OK
#test.example.com.cert.pem: good
#    This Update: ...
#    Next Update: ...
#Response Extensions:
#    OCSP Nonce: 0410...   ← nonce присутствует (мы передали -nonce)
```

### Nonce в OCSP и защита от повторов
Nonce (одноразовое число) в OCSP — расширение с OID 1.3.6.1.5.5.7.48.1.2, которое защищает от атак повтора (replay attacks).

**Как это работает**:
- Клиент генерирует случайное число (nonce) и включает его в OCSP-запрос.
- OCSP-ответчик обязан включить точно такое же значение nonce в ответ.
- Клиент проверяет: nonce в ответе == nonce в запросе. Если нет — ответ отвергается.

**Почему это важно**:
- Без nonce злоумышленник может перехватить старый OCSP-ответ (например, со статусом good) и предъявить его позже, даже если сертификат уже отозван. Nonce делает каждый ответ уникальным и привязанным к конкретному запросу.


## Тестирование
### TEST-1
```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout

# Вывод: 
# Certificate:
#    Data:
#        Version: 3 (0x2)
#        Serial Number:
#            10:05:18:40:9d:72:cc:96:e6:42:24:57:69:2e:e1:91:69:df:ad:74
#        Signature Algorithm: sha256WithRSAEncryption
#        Issuer: CN = Demo Root CA, O = MicroPKI, C = RU
#        Validity
#            Not Before: Mar 16 12:17:10 2026 GMT
#            Not After : Mar 13 12:17:10 2036 GMT
#        Subject: CN = Demo Root CA, O = MicroPKI, C = RU
#        Subject Public Key Info:
#            Public Key Algorithm: rsaEncryption
#                Public-Key: (4096 bit)
#                Modulus:
#                    00:c0:67:e9:49:5f:6f:3b:d1:6d:b0:36:1c:2f:36:
#    .............................................................

openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem

# Вывод: pki/certs/ca.cert.pem: OK
```

### TEST-2
```bash
# Подписать тестовые данные закрытым ключом
echo -n "test message" | openssl dgst -sha256 \
    -sign pki/private/ca.key.pem \
    -out /tmp/test_signature.bin

# (Вводим парольную фразу)

# Извлечь открытый ключ из сертификата
openssl x509 -in pki/certs/ca.cert.pem -pubkey -noout > /tmp/ca_pub.pem

# Проверить подпись открытым ключом из сертификата
echo -n "test message" | openssl dgst -sha256 \
    -verify /tmp/ca_pub.pem \
    -signature /tmp/test_signature.bin

# Ожидаемый вывод: Verified OK
```

### TEST-3
```bash
# Шаг 1: расшифровка ключа (вводим парольную фразу при запросе)
openssl pkey -in pki/private/ca.key.pem -noout
# Ожидаемый вывод: команда завершается без ошибок

# Шаг 2: расшифровать ключ и сразу подписать данные (доказательство загрузки для подписи)
echo -n "test data" | openssl dgst -sha256 \
    -sign pki/private/ca.key.pem \
    -out /tmp/test_sig.bin
# Ожидаемый вывод: вводим парольную фразу, файл подписи создан без ошибок

# Шаг 3: проверка с неправильной парольной фразой
openssl pkey -in pki/private/ca.key.pem -noout -passin pass:wrong_password
# Ожидаемый вывод: ошибка расшифровки

```

### TEST-4A
```bash
# Отсутствует --subject

micropki ca init --passphrase-file secrets/ca.pass
# Ожидаемый результат: ошибка argparse
```

### TEST-4B
```bash
# Неправильный --key-size для ECC

micropki ca init --subject "/CN=Test" --key-type ecc --key-size 4096 --passphrase-file secrets/ca.pass
# Ожидаемый результат: Ошибка: Для ECC, --key-size должен быть 384, получено 4096.
```

### TEST-4C
```bash
# Несуществующий --passphrase-file

micropki ca init --subject "/CN=Test" --passphrase-file nonexistent/file.pass

# Ожидаемый результат: Ошибка: Файл с парольной фразой не существует
```

### TEST-4D
```bash
# Некорректный DN

micropki ca init --subject "invalid-dn" --passphrase-file secrets/ca.pass

# Ожидаемый результат: Ошибка: Некорректный DN component: 'invalid-dn'. Ожидается KEY=VALUE
```

### TEST-5
```bash
# Модульные тесты
pytest

```

### TEST-7
```bash
# Проверка: промежуточный CA подписан корневым CA
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/intermediate.cert.pem

# Ожидаемый результат: pki/certs/intermediate.cert.pem: OK
```

### TEST-7A
```bash
# Проверка: конечный сертификат подписан промежуточным CA,
# а промежуточный — корневым (полная цепочка)
openssl verify \
    -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem
    
# Ожидаемый результат: pki/certs/example.com.cert.pem: OK
```

### TEST-7B
```bash
# Корневой CA — даты действия
openssl x509 -in pki/certs/ca.cert.pem -noout -dates

# Ожидаемый результат: notBefore=Mar 23 12:04:04 2026 GMT
#                      notAfter=Mar 18 12:04:04 2046 GMT
```

### TEST-7C
```bash
# Промежуточный CA — даты действия
openssl x509 -in pki/certs/intermediate.cert.pem -noout -dates

# Ожидаемый результат: notBefore=Mar 23 12:06:59 2026 GMT
#                      notAfter=Mar 22 12:06:59 2031 GMT
```

### TEST-7D
```bash
# Конечный сертификат — даты действия
openssl x509 -in pki/certs/example.com.cert.pem -noout -dates

# Ожидаемый результат: notBefore=Mar 23 12:08:06 2026 GMT
#                      notAfter=Mar 23 12:08:06 2027 GMT
```

### TEST-7E
```bash
# Корневой CA: должен быть CA:TRUE
openssl x509 -in pki/certs/ca.cert.pem -noout -text | grep -A1 "Basic Constraints"

# Ожидаемый результат:    X509v3 Basic Constraints: critical
#                             CA:TRUE  
```

### TEST-7F
```bash
# Промежуточный CA: CA:TRUE, pathlen:0
openssl x509 -in pki/certs/intermediate.cert.pem -noout -text | grep -A1 "Basic Constraints"

# Ожидаемый результат:    X509v3 Basic Constraints: critical
#                             CA:TRUE, pathlen:0
```

### TEST-7G
```bash
# Конечный сертификат: CA:FALSE
openssl x509 -in pki/certs/example.com.cert.pem -noout -text | grep -A1 "Basic Constraints"

# Ожидаемый результат:    X509v3 Basic Constraints: critical
#                             CA:FALSE
```

### TEST-8
```bash
# Расширения корневого CA
openssl x509 -in pki/certs/ca.cert.pem -text -noout

# Ожидаемый результат: Version: 3 (0x2)
# Issuer = Subject (самоподписанный)
# X509v3 Basic Constraints: critical
#       CA:TRUE
# X509v3 Key Usage: critical
#       Digital Signature, Certificate Sign, CRL Sign
# X509v3 Subject Key Identifier: <хеш>
# X509v3 Authority Key Identifier: <совпадает с SKI>
```

### TEST-8A
```bash
# Расширения промежуточного CA
openssl x509 -in pki/certs/intermediate.cert.pem -text -noout

# Ожидаемый результат: Version: 3 (0x2)
# Issuer: CN = Demo Root CA (отличается от Subject)
# Subject: CN = MicroPKI Intermediate CA
# X509v3 Basic Constraints: critical
#       CA:TRUE, pathlen:0
# X509v3 Key Usage: critical
#       Digital Signature, Certificate Sign, CRL Sign
# X509v3 Subject Key Identifier: <хеш>
# X509v3 Authority Key Identifier: <хеш корневого CA>
```

### TEST-8B
```bash
# Расширения серверного сертификата (с SAN)
openssl x509 -in pki/certs/example.com.cert.pem -text -noout

# Ожидаемый результат: Version: 3 (0x2)
# Issuer: CN = MicroPKI Intermediate CA
# X509v3 Basic Constraints: critical
#       CA:FALSE
# X509v3 Key Usage: critical
#       Digital Signature, Key Encipherment
# X509v3 Extended Key Usage:
#       TLS Web Server Authentication
# X509v3 Subject Alternative Name:
#       DNS:example.com, DNS:www.example.com, IP Address:192.168.1.10
# X509v3 Subject Key Identifier: <хеш>
# X509v3 Authority Key Identifier: <хеш промежуточного CA>
```

### TEST-8C
```bash
# Расширения клиентского сертификата
openssl x509 -in pki/certs/Alice_Smith.cert.pem -text -noout

# Ожидаемый результат: X509v3 Basic Constraints: critical
#       CA:FALSE
# X509v3 Key Usage: critical
#       Digital Signature
# X509v3 Extended Key Usage:
#       TLS Web Client Authentication
# X509v3 Subject Alternative Name:
#       email:alice@example.com
```

### TEST-8D
```bash
# Расширения сертификата подписи кода
openssl x509 -in pki/certs/MicroPKI_Code_Signer.cert.pem -text -noout

# Ожидаемый результат: X509v3 Basic Constraints: critical
#       CA:FALSE
# X509v3 Key Usage: critical
#       Digital Signature
# X509v3 Extended Key Usage:
#       Code Signing
```

### TEST-9
```bash
# Создаём файл с полной цепочкой (intermediate + root)
# для использования сервером
cat pki/certs/intermediate.cert.pem pki/certs/ca.cert.pem > pki/certs/chain.pem

# Терминал 1 — запуск TLS-сервера:
openssl s_server \
    -cert pki/certs/example.com.cert.pem \
    -key pki/certs/example.com.key.pem \
    -CAfile pki/certs/ca.cert.pem \
    -chainCAfile pki/certs/chain.pem \
    -accept 4443 \
    -www
    
# Using default temp DH parameters
# ACCEPT

# Терминал 2 — подключение TLS-клиента:

openssl s_client \
    -connect localhost:4443 \
    -CAfile pki/certs/ca.cert.pem \
    -verify 3 \
    -verify_return_error

# Ожидаемый вывод (основное): 
# depth=2 CN = Demo Root CA, O = MicroPKI, C = RU
# verify return:1
# depth=1 CN = MicroPKI Intermediate CA, O = MicroPKI
# verify return:1
# depth=0 CN = example.com, O = MicroPKI
# verify return:1
# ---
# SSL handshake has read 4500 bytes and written 373 bytes
# Verification: OK
# ---
```

### TEST-10
```bash
# Серверный сертификат без SAN
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=no-san.example.com" \
    --out-dir pki/certs

# Ожидаемый результат: Ошибка: Шаблон 'server' требует хотя бы одну запись SAN.
```

### TEST-10A
```bash
# Неподдерживаемый тип SAN для шаблона
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=test.com" \
    --san email:user@test.com \
    --out-dir pki/certs

# Ожидаемый результат: Ошибка: Тип SAN 'email' не допускается для шаблона 'server'. Допустимые: ['dns', 'ip']
```

### TEST-10B
```bash
# Неверная парольная фраза
echo -n "wrong_password" > secrets/wrong.pass

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/wrong.pass \
    --template server \
    --subject "CN=test.com" \
    --san dns:test.com \
    --out-dir pki/certs

# Ожидаемый результат: Ошибка: Incorrect password, could not decrypt key
```

### TEST-10C
```bash
# IP SAN для шаблона подписи кода
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=Code Signer" \
    --san ip:1.2.3.4 \
    --out-dir pki/certs

# Ожидаемый результат: Ошибка: Тип SAN 'ip' не допускается для шаблона 'code_signing'. Допустимые: ['dns', 'uri']
```

### TEST-11
```bash
# Проверка промежуточного CA
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/intermediate.cert.pem

# Ожидаемый результат: pki/certs/intermediate.cert.pem: OK
```

### TEST-11A
```bash
# Проверка конечного сертификата с полной цепочкой
openssl verify \
    -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem

# Ожидаемый результат: pki/certs/example.com.cert.pem: OK
```

### TEST-11B
```bash
# Проверка клиентского сертификата
openssl verify \
    -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/Alice_Smith.cert.pem

# Ожидаемый результат: pki/certs/Alice_Smith.cert.pem: OK
```

### TEST-11C
```bash
# Проверка сертификата подписи кода
openssl verify \
    -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/MicroPKI_Code_Signer.cert.pem

# Ожидаемый результат: pki/certs/MicroPKI_Code_Signer.cert.pem: OK
```

### TEST-12
```bash
# Модульные тесты
pytest

# Ожидаемый результат:
========================================= test session starts ==========================================
configfile: pyproject.toml
collected 31 items

tests/test_csr.py ...                                                                                    [  9%]
tests/test_negative.py ....                                                                              [ 22%]
tests/test_san.py ...........                                                                            [ 58%]
tests/test_templates.py .............                                                                    [100%]

========================================== 31 passed in 2.27s ==========================================
```

### TEST-13
```bash
# Сертификат 1: серверный
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template server --subject "cn=server1.example.com" --san dns:server1.example.com --db-path pki/micropki.db

# Сертификат 2: серверный с несколькими SAN
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template server --subject "cn=server2.example.com" --san dns:server2.example.com --san dns:www.server2.example.com --san ip:10.0.0.2 --db-path pki/micropki.db

# Сертификат 3: клиентский
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template client --subject "cn=alice" --san email:alice@example.com --db-path pki/micropki.db

# Сертификат 4: клиентский
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template client --subject "cn=bob" --san email:bob@example.com --db-path pki/micropki.db

# Сертификат 5: подпись кода
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template code_signing --subject "cn=code signer" --db-path pki/micropki.db

# Проверка: вывести все сертификаты из БД
micropki ca list-certs

# Ожидаемый вывод: 
# Serial           | Subject                        | Not After  | Status
# -----------------+--------------------------------+------------+-------
# 69C42B5FE4242E60 | commonName=code signer         | 2027-03-25 | valid
# 69C42B5A367058FC | commonName=bob                 | 2027-03-25 | valid
# 69C42B558DEEF815 | commonName=alice               | 2027-03-25 | valid
# 69C42B50447D5A48 | commonName=server2.example.com | 2027-03-25 | valid
# 69C42B45108C0DD0 | commonName=server1.example.com | 2027-03-25 | valid
```

### TEST-14
```bash
# Список всех действительных сертификатов
micropki ca list-certs --status valid
# Ожидаемый вывод: таблица с серийными номерами, субъектами, датами, статусами

# Список в формате JSON
micropki ca list-certs --format json
# Ожидаемый вывод: JSON-массив с объектами

# Список в формате CSV
micropki ca list-certs --format csv
# Ожидаемый вывод: CSV с заголовками

# Показать конкретный сертификат
micropki ca show-cert 69C42B45108C0DD0

# Ожидаемый вывод:
# -----BEGIN CERTIFICATE-----
# MIIEbTCCAlWgAwIBAgIIacQrRRCMDdAwDQYJKoZIhvcNAQELBQAwNjEhMB8GA1UE...
# -----END CERTIFICATE-----
```

### TEST-15
```bash

# Запуск сервера (в отдельном терминале)
micropki repo serve --host 127.0.0.1 --port 8080

# В другом терминале:

# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/69C42B45108C0DD0 --output cert.pem
# Ожидаемый вывод: PEM-сертификат

# Сравнить с файлом на диске
diff -s cert.pem pki/certs/server1.example.com.cert.pem
# Ожидаемый вывод: Files cert.pem and pki/certs/server1.example.com.cert.pem are identical
```

### TEST-16
```bash
# Модульные тесты
pytest tests/test_api.py -v

# Ожидаемый результат:
========================================= test session starts ==========================================
configfile: pyproject.toml
collected 4 items

tests/test_api.py::test_get_root_ca PASSED                                                               [ 25%]
tests/test_api.py::test_get_intermediate_ca PASSED                                                       [ 50%]
tests/test_api.py::test_get_ca_unknown_level PASSED                                                      [ 75%]
tests/test_api.py::test_crl_returns_501 PASSED                                                           [100%]

========================================== 4 passed in 5.88s ==========================================
```

### TEST-17, TEST-18
```bash
# Модульные тесты
pytest tests/test_serial.py -v

# Ожидаемый результат:
========================================= test session starts ==========================================
configfile: pyproject.toml
collected 5 items

tests/test_serial.py::test_serial_format PASSED                                                          [ 20%]
tests/test_serial.py::test_serial_to_hex_roundtrip PASSED                                                [ 40%]
tests/test_serial.py::test_is_valid_hex PASSED                                                           [ 60%]
tests/test_serial.py::test_generate_100_unique_serials PASSED                                            [ 80%]
tests/test_serial.py::test_duplicate_serial_rejected PASSED                                              [100%]

========================================== 5 passed in 0.81s ==========================================
```

### TEST-19
```bash
# Сервер должен быть запущен

# Некорректный hex
curl http://localhost:8080/certificate/XYZ
# Ожидаемый вывод: 400 Bad Request, сообщение об ошибке

curl http://localhost:8080/certificate/ZZZZ
# Ожидаемый вывод: 400 Bad Request

# Несуществующий, но валидный hex
curl http://localhost:8080/certificate/DEADBEEF
# Ожидаемый вывод: 404 Not Found
```

### TEST-20
```bash
# Инициализация БД
micropki db init

# Промежуточный CA
micropki ca issue-intermediate --root-cert pki/certs/ca.cert.pem --root-key pki/private/ca.key.pem --root-pass-file secrets/root.pass --subject "CN=Integration Intermediate CA" --passphrase-file secrets/intermediate.pass --db-path pki/micropki.db

# 3 конечных сертификата
micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template server --subject "cn=test1.local" --san dns:test1.local --db-path pki/micropki.db

micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template client --subject "cn=testclient" --san email:test@local.com --db-path pki/micropki.db

micropki ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass --template code_signing --subject "cn=testsigner" --db-path pki/micropki.db

# Проверяем БД
micropki ca list-certs
# Ожидаемый вывод: 4 записи (intermediate + 3 конечных)

# Запуск сервера (в отдельном терминале)
micropki repo serve

# Получение через API
curl http://localhost:8080/certificate/<СЕРИЙНЫЙ_НОМЕР_test1.local> --output cert.pem
# Ожидаемый вывод: PEM-сертификат

# Сравнение
diff -s cert.pem pki/certs/test1.local.cert.pem
# Содержимое из API должно совпадать с файлом pki/certs/test1.local.cert.pem

# Проверка CA-эндпоинтов
curl http://localhost:8080/ca/root
curl http://localhost:8080/ca/intermediate
# Ожидаемый вывод: PEM-сертификаты корневого и промежуточного CA
```

### TEST-21
```bash
# 1. Выпустить серверный сертификат
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "cn=revoke-test.local" \
    --san dns:revoke-test.local \
    --db-path pki/micropki.db

# 2. Проверить статус — должен быть valid
micropki ca list-certs --status valid
# Ожидаемый вывод: запись с revoke-test.local, статус valid

# 3. Отозвать с причиной keyCompromise
micropki ca revoke 69CA97F1887C8399 --reason keyCompromise --force
# Ожидаемый вывод: Сертификат 69CA97F1887C8399 успешно отозван.

# 4. Проверить статус — должен быть revoked
micropki ca list-certs --status revoked
# Ожидаемый вывод: запись с revoke-test.local, статус revoked

# 5. Сгенерировать CRL
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass

# 6. Проверить что CRL содержит отозванный серийный номер
openssl crl -in pki/crl/intermediate.crl.pem -text -noout
# Ожидаемый вывод:
#   Revoked Certificates:
#       Serial Number: 69CA97F1887C8399
#           Revocation Date: Mar 30 15:35:12 2026 GMT
#           CRL entry extensions:
#               X509v3 CRL Reason Code:
#                   Key Compromise

# 7. Запустить сервер и получить CRL через HTTP
micropki repo serve

curl http://localhost:8080/crl -o ca.crl.pem

# Проверяем что CRL одинаковые
openssl crl -in ca.crl.pem -text -noout

# или

diff -s ca.crl.pem pki/crl/intermediate.crl.pem
# Ожидаемый вывод: Files ca.crl.pem and pki/crl/intermediate.crl.pem are identical
```

### TEST-22
```bash
openssl crl -in pki/crl/intermediate.crl.pem -CAfile pki/certs/intermediate.cert.pem -noout
# Ожидаемый вывод: verify OK
```

### TEST-23
```bash
# Первая генерация
micropki ca gen-crl --ca intermediate --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass
openssl crl -in pki/crl/intermediate.crl.pem -text -noout
# Ожидаемый вывод: 
#Certificate Revocation List (CRL):
#        Version 2 (0x1)
#        Signature Algorithm: sha256WithRSAEncryption
#        Issuer: CN = MicroPKI Intermediate CA, O = MicroPKI
#        Last Update: Mar 30 15:46:22 2026 GMT
#        Next Update: Apr  6 15:46:22 2026 GMT
#        CRL extensions:
#            X509v3 CRL Number:
#                3  (номер CRL равен 3)

# Вторая генерация (без новых отзывов)
micropki ca gen-crl --ca intermediate --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/intermediate.pass
openssl crl -in pki/crl/intermediate.crl.pem -text -noout | findstr "CRL Number"
# Ожидаемый вывод: 
#Certificate Revocation List (CRL):
#        Version 2 (0x1)
#        Signature Algorithm: sha256WithRSAEncryption
#        Issuer: CN = MicroPKI Intermediate CA, O = MicroPKI
#        Last Update: Mar 30 15:51:23 2026 GMT
#        Next Update: Apr  6 15:51:23 2026 GMT
#        CRL extensions:
#            X509v3 CRL Number:
#                4  (увеличился на 1)
```

### TEST-24
```bash
micropki ca revoke DEADBEEF12345678 --reason unspecified --force
# Ожидаемый вывод:
# 2026-03-30T18:52:47 ERROR Сертификат не найден в БД: DEADBEEF12345678
# Сертификат с серийным номером DEADBEEF12345678 не найден в базе данных.
```

### TEST-25
```bash
micropki ca revoke 69CA97F1887C8399 --reason superseded --force
# Ожидаемый вывод:
# 2026-03-30T18:54:15 WARNING Сертификат уже отозван: serial=69CA97F1887C8399, subject=commonName=revoke-test.local, причина=keycompromise, дата=2026-03-30T15:35:12Z
# Сертификат 69CA97F1887C8399 уже отозван.
```

### TEST-26
```bash
# Запускаем сервер
micropki repo serve

# Отзываем сертификат
micropki ca revoke 69C42F7CAE83C15A

# Перегенерируем CRL
micropki ca gen-crl \
    --ca intermediate \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass

# Получаем CRL по HTTP
curl http://localhost:8080/crl --output ca.crl.pem

# Сравниваем с локальным файлом:

diff -s ca.crl.pem pki/crl/intermediate.crl.pem
# Ожидаемый вывод: Files ca.crl.pem and pki/crl/intermediate.crl.pem are identical
```

### TEST-28
```bash
# Выпустить сертификат OCSP-ответчика
micropki ca issue-ocsp-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --out-dir pki/certs \
    --db-path pki/micropki.db
# Ожидаемый вывод:
#   ПРЕДУПРЕЖДЕНИЕ: Ключ OCSP-ответчика сохранён без шифрования!
#   Сертификат OCSP-ответчика: pki/certs/OCSP_Responder.cert.pem
#   Ключ OCSP-ответчика: pki/certs/OCSP_Responder.key.pem

# Проверить расширения
openssl x509 -in pki/certs/OCSP_Responder.cert.pem -text -noout
# Ожидаемый вывод (фрагмент):
#   X509v3 Basic Constraints: critical
#       CA:FALSE
#   X509v3 Key Usage: critical
#       Digital Signature
#   X509v3 Extended Key Usage:
#       OCSP Signing
#   (НЕТ keyCertSign, НЕТ cRLSign)

# Проверить что сертификат подписан промежуточным CA
openssl verify \
    -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод: pki/certs/OCSP_Responder.cert.pem: OK
```

### TEST-29
```bash
# Выпустить серверный сертификат для теста
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=ocsp-test.local" \
    --san dns:ocsp-test.local \
    --out-dir pki/certs \
    --db-path pki/micropki.db

# Запустить OCSP-ответчик (в отдельном терминале)
micropki ocsp serve \
    --responder-cert pki/certs/OCSP_Responder.cert.pem \
    --responder-key pki/certs/OCSP_Responder.key.pem \
    --ca-cert pki/certs/intermediate.cert.pem \
    --db-path pki/micropki.db \
    --port 8081

# Запросить статус с nonce и верификацией подписи
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/ocsp-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод:
# Response Extensions:
#         OCSP Nonce:
#             04106765B414A0B3636DB65082DA782E1F86
# Response verify OK
# pki/certs/ocsp-test.local.cert.pem: revoked
#         This Update: Apr  6 15:03:13 2026 GMT
#         Next Update: Apr  6 15:05:13 2026 GMT
#         Reason: keyCompromise
#         Revocation Time: Apr  6 12:02:22 2026 GMT
```

### TEST-30
```bash
# Получить серийный номер сертификата ocsp-test.local
micropki ca list-certs --db-path pki/micropki.db --format json
# Найти serial_hex для CN=ocsp-test.local

# Отозвать сертификат
micropki ca revoke 69D3A07DB8063AE9 \
    --reason keyCompromise \
    --force \
    --db-path pki/micropki.db
# Ожидаемый вывод: Сертификат 69D3A07DB8063AE9 успешно отозван.

# Запросить статус через OCSP (ответчик должен быть запущен)
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/ocsp-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -no_nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод:
# Response verify OK
# pki/certs/ocsp-test.local.cert.pem: revoked
#         This Update: Apr  6 15:05:13 2026 GMT
#         Next Update: Apr  6 15:07:13 2026 GMT
#         Reason: keyCompromise
#         Revocation Time: Apr  6 12:02:22 2026 GMT
```

### TEST-31
```bash
# Запросить несуществующий серийный номер
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -serial 0xDEADBEEF00000001 \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -no_nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод:
# Response verify OK
# 0xDEADBEEF00000001: unknown
#         This Update: Apr  6 15:06:06 2026 GMT
#         Next Update: Apr  6 15:08:06 2026 GMT
```

### TEST-32
```bash
# Запрос С nonce (-nonce)
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/ocsp-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод: 
# Response Extensions:
#         OCSP Nonce:
#             0410AA55864FFD23C7BB31662F2ADADC7295

# Запрос БЕЗ nonce (-no_nonce)
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/ocsp-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -no_nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод: секция "Response Extensions" отсутствует
```

### TEST-33
```bash
# Сохранить ответ в файл
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/ocsp-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -respout pki/ocsp/response.der \
    -no_nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод: Response verify OK

# Верифицировать сохранённый ответ отдельно
openssl ocsp \
    -respin pki/ocsp/response.der \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem \
    -no_nonce
# Ожидаемый вывод: Response verify OK
```

### TEST-34
```bash
# Создать файл с мусорными данными
printf '\x00\x01\x02\x03\xff\xfe' > /tmp/bad_request.der

# Отправить некорректный запрос
curl -s -X POST http://127.0.0.1:8081/ocsp \
    -H "Content-Type: application/ocsp-request" \
    --data-binary @/tmp/bad_request.der \
    -o /tmp/bad_response.der \
    -w "\nHTTP Status: %{http_code}\n"
# Ожидаемый вывод: HTTP Status: 400

# Проверить что ответ — корректный OCSP malformedRequest
openssl ocsp -respin /tmp/bad_response.der -resp_text 2>&1 | head -3
# Ожидаемый вывод:
#   OCSP Response Data:
#       OCSP Response Status: malformedRequest (0x1)
```

### TEST-35
```bash
# Создать сертификат от неизвестного CA
openssl req -x509 -newkey rsa:2048 \
    -keyout /tmp/unknown_ca.key.pem \
    -out /tmp/unknown_ca.cert.pem \
    -days 1 -nodes \
    -subj "/CN=Unknown CA"

openssl req -newkey rsa:2048 \
    -keyout /tmp/foreign.key.pem \
    -out /tmp/foreign.csr.pem \
    -nodes \
    -subj "/CN=foreign.example.com"

openssl x509 -req \
    -in /tmp/foreign.csr.pem \
    -CA /tmp/unknown_ca.cert.pem \
    -CAkey /tmp/unknown_ca.key.pem \
    -CAcreateserial \
    -out /tmp/foreign.cert.pem \
    -days 1

# Запросить статус — издатель не наш CA
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert /tmp/foreign.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -no_nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод:
#   Response verify OK
#   /tmp/foreign.cert.pem: unknown
```


### TEST-37
```bash
# Выпустить новый сертификат
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=integration-test.local" \
    --san dns:integration-test.local \
    --out-dir pki/certs \
    --db-path pki/micropki.db

# Выпустить сертификат OCSP-ответчика
micropki ca issue-ocsp-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --out-dir pki/certs \
    --validity-days 365 \
    --db-path pki/micropki.db

# Запустить OCSP-ответчик
micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path pki/micropki.db \
    --responder-cert pki/certs/OCSP_Responder.cert.pem \
    --responder-key pki/certs/OCSP_Responder.key.pem \
    --ca-cert pki/certs/intermediate.cert.pem \
    --cache-ttl 120

# Проверить работу ответчика
curl http://127.0.0.1:8081/health
# Ожидаемый вывод: {"status":"ok","service":"MicroPKI OCSP Responder"}

# Статус — ожидается good
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/integration-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text -nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод:
#   Response verify OK
#   integration-test.local.cert.pem: good

# Получить серийный номер
micropki ca list-certs --db-path pki/micropki.db
# Найти serial_hex для CN=integration-test.local

# Отозвать
micropki ca revoke 69D39E3502A0098F \
    --reason superseded \
    --force \
    --db-path pki/micropki.db
# Ожидаемый вывод: Сертификат 69D39E3502A0098F успешно отозван.

# Статус — ожидается revoked
openssl ocsp \
    -issuer pki/certs/intermediate.cert.pem \
    -cert pki/certs/integration-test.local.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text -nonce \
    -CAfile pki/certs/ca-chain.pem \
    -verify_other pki/certs/OCSP_Responder.cert.pem
# Ожидаемый вывод:
# Response verify OK
# pki/certs/integration-test.local.cert.pem: revoked
#         This Update: Apr  6 15:11:29 2026 GMT
#         Next Update: Apr  6 15:13:29 2026 GMT
#         Reason: superseded
#         Revocation Time: Apr  6 11:52:38 2026 GMT
```


## Структура выходных файлов
```text
pki/
├── private/
│   ├── intermediate.key.pem # зашифрованный ключ промежуточного CA
│   └── ca.key.pem           # зашифрованный закрытый ключ (PKCS#8)
├── certs/
│   ├── ca.cert.pem                  # сертификат корневого CA
│   ├── intermediate.cert.pem        # сертификат промежуточного CA
│   ├── example.com.cert.pem         # серверный сертификат
│   ├── example.com.key.pem          # незашифрованный ключ сервера
│   ├── Alice_Smith.cert.pem         # клиентский сертификат
│   ├── Alice_Smith.key.pem          # незашифрованный ключ клиента
│   ├── MicroPKI_Code_Signer.cert.pem
│   └── MicroPKI_Code_Signer.key.pem
├── csrs/
│   └── intermediate.csr.pem         # CSR промежуточного CA
├── crl/
│   └── intermediate.crl.pem         # Списко отозванных сертификатов (CRL)
├── ocsp/
│   └── response.der                 # Сохранённые OCSP-ответы (опционально)
├── micropki.db                      # База данных PKI
└── policy.txt            # документ политики УЦ
```

## Структура проекта
```text
MicroPKI/
├── micropki/
│   ├── __init__.py           # пакет
│   ├── cli.py                # парсер аргументов
│   ├── ca.py                 # логика CA
│   ├── certificates.py       # X.509
│   ├── crypto_utils.py       # генерация ключей, PEM, шифрование
│   ├── chain.py              # модуль проверки цепочки сертификатов
│   ├── csr.py                # работа с запросами на сертификат
│   ├── crl.py                # работа с CRL
│   ├── templates.py          # шаблоны сертификатов
│   ├── config.py             # конфиг сервера
│   ├── database.py           # работа с базой данных
│   ├── repository.py         # работа с сертификатами в БД
│   ├── revocation.py         # работа с отзывом сертификатов
│   ├── serial.py             # генератор серийного номера сертификата
│   ├── server.py             # HTTP-сервер
│   ├── ocsp.py               # работа с OCSP
│   ├── ocsp_responder.py     # Сервер OCSP
│   └── logger.py             # настройка логирования
├── tests/
│   ├── test_csr.py           
│   ├── test_negative.py               
│   ├── test_san.py
│   ├── test_api.py 
│   ├── test_serial.py                 
│   └── test_templates.py
├── .gitignore
├── pyproject.toml
├── micropki.conf
└── README.md
```