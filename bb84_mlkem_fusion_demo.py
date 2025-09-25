from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from qunetsim.components import Host
from bb84 import BB84
from mlkem import MLKEM


def classical_protocol(host: Host, middleware_id: str):
    pqc_key = MLKEM.decapsulate(host, middleware_id)

    ciphertext_pqc = host.get_next_classical(middleware_id, wait=-1).content

    f_pqc = Fernet(pqc_key)
    hybrid_key = f_pqc.decrypt(ciphertext_pqc)

    qkd_key = bytes(x ^ y for x, y in zip(pqc_key, hybrid_key))

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,  # Desired length of the derived key in bytes
        salt=None, info=None)

    derived_key = hkdf.derive(pqc_key + qkd_key)
    print(f"[{host.host_id}] Derived Key: {derived_key}")


def middleware_protocol(host: Host, classical_id: str, quantum_id: str):
    pqc_key = MLKEM.encapsulate(host, classical_id)

    qkd_key = BB84.alice_protocol(host, quantum_id)

    hybrid_key = bytes(x ^ y for x, y in zip(pqc_key, qkd_key))

    f_pqc = Fernet(pqc_key)
    ciphertext_pqc = f_pqc.encrypt(hybrid_key)
    host.send_classical(classical_id, ciphertext_pqc, await_ack=True)

    f_qkd = Fernet(qkd_key)
    ciphertext_qkd = f_qkd.encrypt(hybrid_key)
    host.send_classical(quantum_id, ciphertext_qkd, await_ack=True)


def quantum_protocol(host: Host, middleware_id: str):
    qkd_key = BB84.bob_protocol(host, middleware_id)

    ciphertext_qkd = host.get_next_classical(middleware_id, wait=-1).content

    f_qkd = Fernet(qkd_key)
    hybrid_key = f_qkd.decrypt(ciphertext_qkd)

    pqc_key = bytes(x ^ y for x, y in zip(qkd_key, hybrid_key))

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,  # Desired length of the derived key in bytes
        salt=None, info=None)

    derived_key = hkdf.derive(pqc_key + qkd_key)
    print(f"[{host.host_id}] Derived Key: {derived_key}")
