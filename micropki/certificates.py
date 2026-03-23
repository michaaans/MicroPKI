"""
Работа с сертификатами X.509 v3:
- парсинг строки DN (два формата)
- построение самоподписанного корневого сертификата
- построение промежуточного сертификата (подписанного корневым)
- построение конечных сертификатов по шаблонам
- парсинг записей SAN
- сериализация сертификата в PEM
"""

import os
import datetime
import ipaddress
from typing import Union

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from micropki.templates import CertificateTemplate, build_key_usage

# Маппинг коротких имён атрибутов DN → OID
_OID_MAP: dict[str, x509.ObjectIdentifier] = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "EMAIL": NameOID.EMAIL_ADDRESS,
}


def parse_subject_dn(subject_str: str) -> x509.Name:
    """
    Парсит строку Distinguished Name в x509.Name.

    Поддерживает:
      /CN=My Root CA/O=Demo/C=US   (нотация с косой чертой)
      CN=My Root CA,O=Demo,C=US    (нотация через запятую)

    :param subject_str: строка DN
    :return: объект x509.Name
    :raises ValueError: при некорректном формате
    """
    subject_str = subject_str.strip()
    if not subject_str:
        raise ValueError("DN субъекта не должен быть пустым")

    if subject_str.startswith("/"):
        parts = subject_str.lstrip("/").split("/")
    else:
        parts = subject_str.split(",")

    if not parts:
        raise ValueError("DN субъекта пуст после разбора")

    attributes: list[x509.NameAttribute] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue

        if "=" not in part:
            raise ValueError(
                f"Некорректный компонент DN: '{part}'. Ожидается формат KEY=VALUE"
            )

        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()

        if key not in _OID_MAP:
            raise ValueError(
                f"Неизвестный атрибут DN: '{key}'. "
                f"Поддерживаемые: {sorted(_OID_MAP.keys())}"
            )

        if not value:
            raise ValueError(f"Пустое значение для атрибута DN '{key}'")

        attributes.append(x509.NameAttribute(_OID_MAP[key], value))

    if not attributes:
        raise ValueError("DN субъекта не содержит валидных атрибутов")

    return x509.Name(attributes)


def _generate_serial_number() -> int:
    """
    Генерирует серийный номер для сертификата.

    20 байт случайных данных, старший бит обнулён (≤ 159 бит),
    гарантированно положительный.

    :return: положительное целое число
    """
    raw = bytearray(os.urandom(20))
    raw[0] &= 0x7F
    serial = int.from_bytes(raw, byteorder="big")
    return serial if serial != 0 else 1


def _get_signing_hash(key_type: str) -> hashes.HashAlgorithm:
    """
    Возвращает алгоритм хеширования для подписи.

    :param key_type: 'rsa' или 'ecc'
    :return: SHA256 для RSA, SHA384 для ECC
    """
    if key_type == "rsa":
        return hashes.SHA256()
    if key_type == "ecc":
        return hashes.SHA384()
    raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")


def _detect_key_type(private_key: PrivateKeyTypes) -> str:
    """
    Определяет тип ключа по объекту закрытого ключа.

    :param private_key: объект закрытого ключа
    :return: 'rsa' или 'ecc'
    """
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod
    if isinstance(private_key, rsa_mod.RSAPrivateKey):
        return "rsa"
    if isinstance(private_key, ec_mod.EllipticCurvePrivateKey):
        return "ecc"
    raise ValueError(f"Неподдерживаемый тип ключа: {type(private_key)}")


def build_root_ca_certificate(
    private_key: PrivateKeyTypes,
    subject: x509.Name,
    validity_days: int,
    key_type: str,
) -> x509.Certificate:
    """
    Создаёт самоподписанный сертификат корневого УЦ.

    :param private_key: закрытый ключ корневого CA
    :param subject: DN субъекта
    :param validity_days: срок действия в днях
    :param key_type: 'rsa' или 'ecc'
    :return: подписанный сертификат X.509 v3
    """
    public_key = private_key.public_key()
    serial_number = _generate_serial_number()

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)
    signing_hash = _get_signing_hash(key_type)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(not_after)
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = builder.add_extension(ski, critical=False)

    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    builder = builder.add_extension(aki, critical=False)

    return builder.sign(private_key=private_key, algorithm=signing_hash)


def build_intermediate_certificate(
    csr: x509.CertificateSigningRequest,
    root_private_key: PrivateKeyTypes,
    root_cert: x509.Certificate,
    validity_days: int,
    path_length: int,
) -> x509.Certificate:
    """
    Подписывает CSR промежуточного CA закрытым ключом корневого CA.

    Создаёт сертификат X.509 v3 с:
    - Издатель = субъект корневого CA
    - BasicConstraints: CA=TRUE, pathLenConstraint = path_length
    - KeyUsage: keyCertSign, cRLSign
    - SKI из открытого ключа промежуточного CA
    - AKI из SKI корневого CA

    :param csr: CSR промежуточного CA
    :param root_private_key: закрытый ключ корневого CA
    :param root_cert: сертификат корневого CA
    :param validity_days: срок действия
    :param path_length: ограничение длины пути
    :return: подписанный сертификат промежуточного CA
    """
    root_key_type = _detect_key_type(root_private_key)
    signing_hash = _get_signing_hash(root_key_type)
    serial_number = _generate_serial_number()

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    intermediate_public_key = csr.public_key()

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(not_after)
    )

    # BasicConstraints: CA=TRUE с ограничением длины пути
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True,
    )

    # KeyUsage: keyCertSign + cRLSign
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # SKI — из открытого ключа промежуточного CA
    ski = x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key)
    builder = builder.add_extension(ski, critical=False)

    # AKI — из SKI корневого CA
    root_ski_ext = root_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        root_ski_ext.value
    )
    builder = builder.add_extension(aki, critical=False)

    return builder.sign(private_key=root_private_key, algorithm=signing_hash)


def parse_san_entries(san_strings: list[str]) -> list[tuple[str, str]]:
    """
    Парсит строки SAN формата 'тип:значение'.

    Поддерживаемые типы: dns, ip, email, uri.

    :param san_strings: список строк, например ["dns:example.com", "ip:1.2.3.4"]
    :return: список кортежей (тип, значение)
    :raises ValueError: при некорректном формате
    """
    supported_types = {"dns", "ip", "email", "uri"}
    entries: list[tuple[str, str]] = []

    for s in san_strings:
        if ":" not in s:
            raise ValueError(
                f"Некорректный формат SAN: '{s}'. Ожидается 'тип:значение'"
            )

        san_type, san_value = s.split(":", 1)
        san_type = san_type.strip().lower()
        san_value = san_value.strip()

        if san_type not in supported_types:
            raise ValueError(
                f"Неподдерживаемый тип SAN: '{san_type}'. "
                f"Допустимые: {sorted(supported_types)}"
            )

        if not san_value:
            raise ValueError(f"Пустое значение для SAN типа '{san_type}'")

        entries.append((san_type, san_value))

    return entries


def build_san_extension(
    san_entries: list[tuple[str, str]],
) -> x509.SubjectAlternativeName | None:
    """
    Строит расширение SubjectAlternativeName из списка записей.

    :param san_entries: список кортежей (тип, значение)
    :return: объект SubjectAlternativeName или None если список пуст
    :raises ValueError: при некорректном IP-адресе
    """
    if not san_entries:
        return None

    general_names: list[x509.GeneralName] = []

    for san_type, san_value in san_entries:
        if san_type == "dns":
            general_names.append(x509.DNSName(san_value))
        elif san_type == "ip":
            try:
                ip = ipaddress.ip_address(san_value)
            except ValueError:
                raise ValueError(f"Некорректный IP-адрес в SAN: '{san_value}'")
            general_names.append(x509.IPAddress(ip))
        elif san_type == "email":
            general_names.append(x509.RFC822Name(san_value))
        elif san_type == "uri":
            general_names.append(
                x509.UniformResourceIdentifier(san_value)
            )

    return x509.SubjectAlternativeName(general_names)


def build_leaf_certificate(
    subject: x509.Name,
    leaf_public_key,
    ca_private_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    template: CertificateTemplate,
    san_entries: list[tuple[str, str]],
    validity_days: int,
    leaf_key_type: str,
) -> x509.Certificate:
    """
    Строит и подписывает конечный сертификат по шаблону.

    :param subject: DN субъекта конечного сертификата
    :param leaf_public_key: открытый ключ конечного субъекта
    :param ca_private_key: закрытый ключ промежуточного CA
    :param ca_cert: сертификат промежуточного CA
    :param template: шаблон сертификата
    :param san_entries: записи SAN
    :param validity_days: срок действия
    :param leaf_key_type: тип ключа конечного субъекта ('rsa' или 'ecc')
    :return: подписанный сертификат
    """
    ca_key_type = _detect_key_type(ca_private_key)
    signing_hash = _get_signing_hash(ca_key_type)
    serial_number = _generate_serial_number()

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_public_key)
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(not_after)
    )

    # BasicConstraints: CA=FALSE, критическое
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    # KeyUsage по шаблону, критическое
    key_usage = build_key_usage(template, leaf_key_type)
    builder = builder.add_extension(key_usage, critical=True)

    # Extended Key Usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(template.extended_key_usages),
        critical=False,
    )

    # SAN (если есть)
    san_ext = build_san_extension(san_entries)
    if san_ext is not None:
        builder = builder.add_extension(san_ext, critical=False)

    # SKI — из открытого ключа конечного субъекта
    ski = x509.SubjectKeyIdentifier.from_public_key(leaf_public_key)
    builder = builder.add_extension(ski, critical=False)

    # AKI — из SKI промежуточного CA
    ca_ski_ext = ca_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        ca_ski_ext.value
    )
    builder = builder.add_extension(aki, critical=False)

    return builder.sign(private_key=ca_private_key, algorithm=signing_hash)


def serialize_certificate_pem(certificate: x509.Certificate) -> bytes:
    """
    Сертификат → PEM-байты.

    :param certificate: объект сертификата
    :return: байты в формате PEM
    """
    return certificate.public_bytes(serialization.Encoding.PEM)