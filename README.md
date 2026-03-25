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

# CRL (заглушка)
curl http://localhost:8080/crl

# Некорректный серийный номер
curl http://localhost:8080/certificate/XYZ
```

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
│   ├── templates.py          # шаблоны сертификатов
│   ├── config.py             # конфиг сервера
│   ├── database.py           # работа с базой данных
│   ├── repository.py         # работа с сертификатами в БД
│   ├── serial.py             # генератор серийного номера сертификата
│   ├── server.py             # HTTP-сервер
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