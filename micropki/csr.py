"""
Модуль для работы с запросами на сертификат (CSR / PKCS#10).

Содержит:
- генерацию CSR для промежуточного УЦ
- парсинг и валидацию CSR
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def build_intermediate_csr(
    private_key: PrivateKeyTypes,
    subject: x509.Name,
    path_length: int,
    key_type: str,
) -> x509.CertificateSigningRequest:
    """
    Создаёт CSR (PKCS#10) для промежуточного удостоверяющего центра.

    CSR подписывается закрытым ключом промежуточного CA
    (доказательство владения ключом).

    :param private_key: закрытый ключ промежуточного CA
    :param subject: DN субъекта промежуточного CA
    :param path_length: ограничение длины пути (pathLenConstraint)
    :param key_type: 'rsa' или 'ecc' — для выбора алгоритма хеширования
    :return: объект CSR
    """
    if key_type == "rsa":
        signing_hash = hashes.SHA256()
    elif key_type == "ecc":
        signing_hash = hashes.SHA384()
    else:
        raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
    )

    # Добавляем BasicConstraints в CSR как запрошенное расширение
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True,
    )

    csr = builder.sign(
        private_key=private_key,
        algorithm=signing_hash,
    )

    return csr


def serialize_csr_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """
    Сериализует CSR в формат PEM.

    :param csr: объект CSR
    :return: байты PEM-файла
    """
    from cryptography.hazmat.primitives import serialization
    return csr.public_bytes(serialization.Encoding.PEM)