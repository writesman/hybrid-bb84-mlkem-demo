import random
import numpy as np
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit
from quantcrypt.kem import MLKEM_1024
from cryptography.fernet import Fernet
import hashlib
import base64
from math import ceil

NETWORK_TIMEOUT = 180
QKD_QUBIT_RATIO = 5.0


def classical_sender_protocol(host: Host, receiver_id: Host.host_id, message: str, kem):
    public_key_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if public_key_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for public key from [{receiver_id}].")
        return
    public_key = public_key_obj.content
    print(f"[{host.host_id}] Received public key from [{receiver_id}].")

    print(f"[{host.host_id}] Generated KEM ciphertext and shared secret.")
    ciphertext, shared_secret = kem.encaps(public_key)

    print(f"[{host.host_id}] Sending KEM ciphertext to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext, await_ack=True)

    raw_key = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(raw_key)
    sender_fernet = Fernet(fernet_key)

    encrypted_message = sender_fernet.encrypt(message.encode())

    print(f"[{host.host_id}] Sending Fernet-encrypted message to [{receiver_id}].")
    host.send_classical(receiver_id, encrypted_message, await_ack=True)


def classical_receiver_protocol(host: Host, sender_id: Host.host_id, kem):
    print(f"[{host.host_id}] Generated KEM key pair.")
    public_key, secret_key = kem.keygen()

    print(f"[{host.host_id}] Sending public key to [{sender_id}].")
    host.send_classical(sender_id, public_key, await_ack=True)

    ciphertext_obj = host.get_next_classical(sender_id, wait=-1)
    if ciphertext_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for ciphertext from [{sender_id}].")
        return None
    ciphertext = ciphertext_obj.content
    print(f"[{host.host_id}] Received KEM ciphertext from [{sender_id}].")

    shared_secret = kem.decaps(secret_key, ciphertext)

    raw_key = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(raw_key)
    receiver_fernet = Fernet(fernet_key)

    encrypted_message_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if encrypted_message_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for encrypted message from [{sender_id}].")
        return None
    encrypted_message = encrypted_message_obj.content
    print(f"[{host.host_id}] Received Fernet-encrypted message from [{sender_id}].")

    decrypted_message = receiver_fernet.decrypt(encrypted_message).decode()

    print(f"[{host.host_id}] Successfully decrypted classical message: '{decrypted_message}'")

    return decrypted_message


def apply_one_time_pad(binary_input: str, key: str) -> str:
    if len(key) < len(binary_input):
        raise ValueError("One-Time Pad key cannot be shorter than the message.")

    input_int = int(binary_input, 2)
    key_int = int(key[:len(binary_input)], 2)

    result_int = input_int ^ key_int

    result_binary = format(result_int, f'0{len(binary_input)}b')
    return result_binary


def binary_to_text(binary_string: str) -> str:
    byte_chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    byte_list = [int(chunk, 2) for chunk in byte_chunks]
    return bytes(byte_list).decode('utf-8', 'ignore')


def e91_sift_and_test(host: Host, partner_id: str, my_bases: list, my_meas: list, is_initiator: bool):
    # Step 1: Exchange bases
    if is_initiator:
        host.send_classical(partner_id, my_bases, await_ack=True)
        their_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_bases_obj is None: return None
        their_bases = their_bases_obj.content
        bases_a = my_bases
        bases_b = their_bases
    else:
        their_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_bases_obj is None: return None
        their_bases = their_bases_obj.content
        host.send_classical(partner_id, my_bases, await_ack=True)
        bases_a = their_bases
        bases_b = my_bases

    # Step 2: Identify key qubits and test qubits
    sifted_key_indices = []
    test_indices = []
    for i in range(min(len(bases_a), len(bases_b))):
        if np.isclose(bases_a[i], np.pi/4) and np.isclose(bases_b[i], np.pi/4):
            sifted_key_indices.append(i)
        else:
            test_indices.append(i)

    # Step 3: Exchange measurement outcomes ONLY for test qubits
    my_test_meas = {i: my_meas[i] for i in test_indices}
    if is_initiator:
        host.send_classical(partner_id, my_test_meas, await_ack=True)
        their_test_meas_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_test_meas_obj is None: return None
        their_test_meas = their_test_meas_obj.content
    else:
        their_test_meas_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_test_meas_obj is None: return None
        their_test_meas = their_test_meas_obj.content
        host.send_classical(partner_id, my_test_meas, await_ack=True)

    test_meas_a = my_test_meas if is_initiator else their_test_meas
    test_meas_b = their_test_meas if is_initiator else my_test_meas

    # Step 4: Perform Bell Test
    if not test_indices:
        print(f"[{host.host_id}] No cases available for Bell test. Aborting.")
        return None

    correlation = sum(1 for i in test_indices if test_meas_a.get(i) == test_meas_b.get(i))
    correlation_ratio = correlation / len(test_indices)

    # In an ideal simulation, a correlation ratio of 1.0 is suspicious, as test bases should differ.
    if correlation_ratio < 0.9:
        print(f"[{host.host_id}] Bell test PASSED. Correlation ratio is {correlation_ratio:.3f}.")
        final_key = "".join([str(my_meas[i]) for i in sifted_key_indices])
        return final_key
    else:
        print(f"[{host.host_id}] Bell test FAILED. Suspiciously high correlation: {correlation_ratio:.3f}.")
        return None


def quantum_sender_protocol(host: Host, receiver_id: Host.host_id, message: str):
    message_binary = ''.join(format(byte, '08b') for byte in message.encode())
    required_key_len = len(message_binary)
    num_pairs = ceil(required_key_len * QKD_QUBIT_RATIO)

    host.send_classical(receiver_id, num_pairs, await_ack=True)
    print(f"[{host.host_id}] Establishing {num_pairs} EPR pairs with [{receiver_id}].")

    epr_ids = []
    for i in range(num_pairs):
        epr_id, _ = host.send_epr(receiver_id, await_ack=True)
        epr_ids.append(epr_id)

    bases_a = [random.choice([0, np.pi/4]) for _ in range(num_pairs)]
    meas_a = []
    for i in range(num_pairs):
        q = host.get_epr(receiver_id, epr_ids[i])
        if q:
            q.ry(bases_a[i])
            meas_a.append(q.measure())

    one_time_pad_key = e91_sift_and_test(host, receiver_id, bases_a, meas_a, is_initiator=True)

    if one_time_pad_key is None or len(one_time_pad_key) < required_key_len:
        print(f"CRITICAL: [{host.host_id}] Protocol aborted. Key generation failed or key too short.")
        return

    ciphertext_binary = apply_one_time_pad(message_binary, one_time_pad_key)
    print(f"[{host.host_id}] Encrypted message with one-time pad, sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext_binary, await_ack=True)


def quantum_receiver_protocol(host: Host, sender_id: Host.host_id):
    msg = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if msg is None: return None
    num_pairs = int(msg.content)
    print(f"[{host.host_id}] Awaiting {num_pairs} EPR pairs from [{sender_id}].")

    bases_b = [random.choice([np.pi/4, np.pi/2]) for _ in range(num_pairs)]
    meas_b = []
    for _ in range(num_pairs):
        q = host.get_epr(sender_id, wait=NETWORK_TIMEOUT)
        if q:
            basis = bases_b[len(meas_b)]
            q.ry(basis)
            meas_b.append(q.measure())

    one_time_pad_key = e91_sift_and_test(host, sender_id, bases_b, meas_b, is_initiator=False)

    if one_time_pad_key is None:
        return None

    encrypted_message = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if encrypted_message is None:
        print(f"[{host.host_id}] Timed out waiting for final message from [{sender_id}]. Sender may have aborted.")
        return None

    ciphertext_binary = encrypted_message.content
    decrypted_binary = apply_one_time_pad(ciphertext_binary, one_time_pad_key)
    decrypted_message = binary_to_text(decrypted_binary)

    print(f"[{host.host_id}] Successfully decrypted quantum message: '{decrypted_message}'")
    return decrypted_message


def middleware_classical_to_quantum(host: Host, classical_id: Host.host_id, quantum_id: Host.host_id, kem):
    message = classical_receiver_protocol(host, classical_id, kem)
    if message:
        quantum_sender_protocol(host, quantum_id, message)


def middleware_quantum_to_classical(host: Host, classical_id: Host.host_id, quantum_id: Host.host_id, kem):
    message = quantum_receiver_protocol(host, quantum_id)
    if message:
        classical_sender_protocol(host, classical_id, message, kem)


if __name__ == '__main__':
    kem = MLKEM_1024()
    network = Network.get_instance()
    network.start()

    host_classical = Host('Classical Node')
    host_middleware = Host('Middleware Node')
    host_quantum = Host('Quantum Node')

    host_classical.add_c_connection('Middleware Node')
    host_middleware.add_c_connection('Classical Node')
    host_middleware.add_connection('Quantum Node')
    host_quantum.add_connection('Middleware Node')

    host_classical.start()
    host_middleware.start()
    host_quantum.start()
    network.add_hosts([host_classical, host_middleware, host_quantum])

    print(f"## Starting Classical-to-Quantum simulation... ##")
    c2q_message = "He!"
    thread_c2q_classical = host_classical.run_protocol(
        classical_sender_protocol,(host_middleware.host_id, c2q_message, kem))
    thread_c2q_middleware = host_middleware.run_protocol(
        middleware_classical_to_quantum,(host_classical.host_id, host_quantum.host_id, kem))
    thread_c2q_quantum = host_quantum.run_protocol(quantum_receiver_protocol, (host_middleware.host_id,))
    thread_c2q_classical.join()
    thread_c2q_middleware.join()
    thread_c2q_quantum.join()
    print("## Classical-to-Quantum Simulation Complete ##\n")

    print(f"## Starting Quantum-to-Classical simulation... ##")
    q2c_message = "Hello Classical!"
    thread_q2c_quantum = host_quantum.run_protocol(
        quantum_sender_protocol, (host_middleware.host_id, q2c_message))
    thread_q2c_middleware = host_middleware.run_protocol(
        middleware_quantum_to_classical, (host_classical.host_id, host_quantum.host_id, kem))
    thread_q2c_classical = host_classical.run_protocol(
        classical_receiver_protocol, (host_middleware.host_id, kem))
    thread_q2c_quantum.join()
    thread_q2c_middleware.join()
    thread_q2c_classical.join()
    print("## Quantum-to-Classical Simulation Complete ##")

    network.stop()
