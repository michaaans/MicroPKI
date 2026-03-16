"""
Работа с сертификатами X.509 v3:
- парсинг строки DN (два формата)
- построение самоподписанного корневого сертификата
- сериализация сертификата в PEM
"""

import os
import datetime
from typing import List, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

# Маппинг коротких имён атрибутов DN → OID
_OID_MAP: dict[str, x509.ObjectIdentifier] = {
    "CN": NameOID.COMMON_NAME,
    "O":  NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C":  NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L":  NameOID.LOCALITY_NAME,
}


def parse_subject_dn(subject_str: str) -> x509.Name:
    """
    Парсит строку Distinguished Name в x509.Name.

    Поддерживает:
      /CN=My Root CA/O=Demo/C=US   (нотация с косой чертой)
      CN=My Root CA,O=Demo,C=US    (нотация через запятую)

    Raise:
      ValueError — при пустой строке, неизвестном атрибуте,
                   отсутствии знака '=' или пустом значении.
    """
    subject_str = subject_str.strip()
    if not subject_str:
        raise ValueError("Subject DN не может быть пустым")

    # Определяем формат и разбиваем
    if subject_str.startswith("/"):
        parts = subject_str.lstrip("/").split("/")
    else:
        parts = _split_comma_dn(subject_str)

    if not parts:
        raise ValueError("Subject DN пустой после парсинга")

    attributes: list[x509.NameAttribute] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue

        if "=" not in part:
            raise ValueError(
                f"Некорректный DN component: '{part}'. Ожидается KEY=VALUE"
            )

        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()

        if key not in _OID_MAP:
            raise ValueError(
                f"Неизвестный DN атрибут: '{key}'. "
                f"Поддерживаемые: {sorted(_OID_MAP.keys())}"
            )

        if not value:
            raise ValueError(f"Пустой значение для DN атрибута '{key}'")

        attributes.append(x509.NameAttribute(_OID_MAP[key], value))

    if not attributes:
        raise ValueError("Subject DN produced no valid attributes")

    return x509.Name(attributes)


def _split_comma_dn(dn: str) -> list[str]:
    """
    Разделяет DN по запятым, но учитывает, что значение
    может содержать запятую внутри кавычек (упрощённая версия).
    Для учебного проекта достаточно простого split.
    """
    return dn.split(",")


def build_root_ca_certificate(
    private_key: PrivateKeyTypes,
    subject: x509.Name,
    validity_days: int,
    key_type: str,
) -> x509.Certificate:
    """
    Строит и подписывает самоподписанный сертификат X.509 v3
    корневого удостоверяющего центра.
    """
    public_key = private_key.public_key()

    raw = bytearray(os.urandom(20))
    raw[0] &= 0x7F
    serial_number = int.from_bytes(raw, byteorder="big")
    if serial_number == 0:
        serial_number = 1    # серийный номер обязан быть положительным

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=validity_days)

    # --- дальше всё без изменений ---
    if key_type == "rsa":
        signing_hash = hashes.SHA256()
    elif key_type == "ecc":
        signing_hash = hashes.SHA384()
    else:
        raise ValueError(f"Unsupported key type for signing: {key_type}")

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

    certificate = builder.sign(
        private_key=private_key,
        algorithm=signing_hash,
    )

    return certificate


def serialize_certificate_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)