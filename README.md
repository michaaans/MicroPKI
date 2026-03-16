# MicroPKI

Минималистичный инструмент для создания инфраструктуры открытых ключей (PKI) в учебных целях.

## Зависимости

- Python 3.10+
- OpenSSL
- `cryptography` >= 46.0.0

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
```

## Использование
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

## Структура выходных файлов
```text
pki/
├── private/
│   └── ca.key.pem        # зашифрованный закрытый ключ (PKCS#8)
├── certs/
│   └── ca.cert.pem       # самоподписанный сертификат X.509 v3
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
│   └── logger.py             # настройка логирования
├── tests/
├── .gitignore
├── pyproject.toml
└── README.md
```