import base64
import hashlib
import numpy as np
from cryptography.fernet import Fernet
from math import ceil
from quantcrypt.kem import MLKEM_1024
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit
from qunetsim.objects import Logger
from random import randint
import random


# #############################################################################
# Global
# #############################################################################

Logger.DISABLED = True
NETWORK_TIMEOUT = 20
QKD_CHECK_RATIO = 0.5
QKD_QUBIT_RATIO = 5.0


# #############################################################################
# Utilities
# #############################################################################

def apply_one_time_pad(binary_input: str, key: str) -> str:
    """Encrypts or decrypts a binary string using a one-time pad key."""
    if len(key) < len(binary_input):
        raise ValueError("One-Time Pad key cannot be shorter than the message.")
    input_int = int(binary_input, 2)
    key_int = int(key[:len(binary_input)], 2)
    result_int = input_int ^ key_int
    return format(result_int, f'0{len(binary_input)}b')


def binary_to_text(binary_string: str) -> str:
    """Converts a binary string back into a human-readable text string."""
    byte_chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    byte_list = [int(chunk, 2) for chunk in byte_chunks]
    return bytes(byte_list).decode('utf-8', 'ignore')


# #############################################################################
# Classical Protocols
# #############################################################################

def classical_receiver_protocol(host: Host, sender_id: Host.host_id, kem):
    """Protocol for a classical node to receive an encrypted message."""
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


def classical_sender_protocol(host: Host, receiver_id: Host.host_id, message: str, kem):
    """Protocol for a classical node to send an encrypted message."""
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


# #############################################################################
# B92 QKD Protocols
# #############################################################################

def generate_key(key_length):
    generated_key = []
    for i in range(key_length):
        generated_key.append(randint(0, 1))
    print(f'Generated the key {generated_key}')
    return generated_key


def b92_receiver_protocol(host: Host, sender_id: Host.host_id):
    def _check_key_receiver(bob, key_check_bob, sender):
        key_check_bob_string = ''.join([str(x) for x in key_check_bob])
        print(f'Bob\'s key to check is {key_check_bob_string}')

        key_from_alice_obj = bob.get_next_classical(sender, wait=20)
        if key_from_alice_obj is None:
            print(f"[{bob.host_id}] Timed out waiting for key check from [{sender}]")
            return

        if key_from_alice_obj.content == key_check_bob_string:
            bob.send_classical(sender, 'Success', await_ack=True)
        else:
            bob.send_classical(sender, 'Fail', await_ack=True)

    def _receiver_qkd(bob, key_size, sender):
        key_array = []
        received_counter = 0
        # counts the key bits successfully measured by Bob
        while received_counter < key_size:
            base = randint(0, 1)
            # 0 means rectilinear basis and 1 means diagonal basis
            qubit = bob.get_qubit(sender, wait=NETWORK_TIMEOUT)
            if qubit is not None:
                if base == 1:
                    qubit.H()
                bit = qubit.measure()
                if bit == 1:
                    if base == 1:
                        resulting_key_bit = 0
                    elif base == 0:
                        resulting_key_bit = 1
                    message_to_send = 'qubit successfully acquired'
                    key_array.append(resulting_key_bit)
                    received_counter += 1
                    print(f'Bob received qubit {received_counter}')
                else:
                    message_to_send = 'fail'
                bob.send_classical(sender, message_to_send, await_ack=True)
        return key_array

    key_info_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if key_info_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for key info from [{sender_id}].")
        return None

    content = key_info_obj.content
    if not content.startswith("KEY_INFO:"):
        print(f"ERROR: [{host.host_id}] received invalid key info format.")
        return None

    parts = content.split(':')
    key_length = int(parts[1])
    key_check_length = int(parts[2])
    print(f"[{host.host_id}] Received QKD parameters from [{sender_id}].")

    secret_key_bob = _receiver_qkd(host, key_length, sender_id)
    key_to_test = secret_key_bob[0:key_check_length]
    _check_key_receiver(host, key_to_test, sender_id)

    encrypted_message = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if encrypted_message is None:
        print(f"[{host.host_id}] Timed out waiting for final message from [{sender_id}]. Sender may have aborted.")
        return None

    ciphertext_binary = encrypted_message.content

    one_time_pad_key_list = secret_key_bob[key_check_length:]

    one_time_pad_key_string = ''.join(map(str, one_time_pad_key_list))

    decrypted_binary = apply_one_time_pad(ciphertext_binary, one_time_pad_key_string)
    decrypted_message = binary_to_text(decrypted_binary)

    print(f"[{host.host_id}] Successfully decrypted quantum message: '{decrypted_message}'")

    return decrypted_message


def b92_sender_protocol(host: Host, receiver_id: Host.host_id, message: str):
    def _check_key_sender(alice, key_check_alice, receiver):
        key_check_string = ''.join([str(x) for x in key_check_alice])
        print(f'Alice\'s key to check is {key_check_string}')
        alice.send_classical(receiver, key_check_string, await_ack=True)

        message_from_bob = alice.get_next_classical(receiver, wait=20)
        if message_from_bob is None:
            print(f"Alice timed out waiting for key verification from Bob")
            return False

        if message_from_bob.content == 'Success':
            print('Key is successfully verified')
            return True
        else:
            print('Key has been corrupted')
            return False

    def _sender_qkd(alice, secret_key, receiver):
        sent_qubit_counter = 0
        for bit in secret_key:
            success = False
            while success == False:
                qubit = Qubit(alice)
                if bit == 1:
                    qubit.H()
                # If we want to send 0, we'll send |0>
                # If we want to send 1, we'll send |+>
                alice.send_qubit(receiver, qubit, await_ack=True)
                message = alice.get_next_classical(receiver, wait=20)  # Changed wait time
                if message is not None:
                    if message.content == 'qubit successfully acquired':
                        print(f'Alice sent qubit {sent_qubit_counter + 1} to Bob')
                        success = True
                        sent_qubit_counter += 1
                else:
                    print(f"[{alice.host_id}] Timed out waiting for ACK on qubit {sent_qubit_counter + 1}. Resending.")
                    # The loop will continue, causing a resend.

    message_binary = ''.join(format(byte, '08b') for byte in message.encode())

    key_check_length = ceil(len(message_binary) * QKD_CHECK_RATIO)
    key_length = len(message_binary) + key_check_length

    key_info_message = f"KEY_INFO:{key_length}:{key_check_length}"
    print(f"[{host.host_id}] Announcing QKD parameters to [{receiver_id}]: {key_info_message}")
    host.send_classical(receiver_id, key_info_message, await_ack=True)

    encryption_key_binary = generate_key(key_length)
    _sender_qkd(host, encryption_key_binary, receiver_id)
    print(f"[{host.host_id}] All QKD qubits sent to [{receiver_id}].")

    key_to_test = encryption_key_binary[0:key_check_length]

    keys_are_secure = _check_key_sender(host, key_to_test, receiver_id)
    if not keys_are_secure:
        print(f"CRITICAL: [{host.host_id}] Protocol aborted due to key check failure.")
        return

    one_time_pad_key_list = encryption_key_binary[key_check_length:]
    one_time_pad_key_string = ''.join(map(str, one_time_pad_key_list))

    ciphertext_binary = apply_one_time_pad(message_binary, one_time_pad_key_string)

    print(f"[{host.host_id}] Encrypted message with one-time pad, sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext_binary, await_ack=True)


# #############################################################################
# E91 Protocols
# #############################################################################

def e91_sift_and_test(host: Host, partner_id: str, my_bases: list, my_meas: list, is_initiator: bool):
    # Step 1: Exchange bases
    if is_initiator:
        host.send_classical(partner_id, my_bases, await_ack=True)
        their_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_bases_obj is None:
            return None
        their_bases = their_bases_obj.content
        bases_a = my_bases
        bases_b = their_bases
    else:
        their_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_bases_obj is None:
            return None
        their_bases = their_bases_obj.content
        host.send_classical(partner_id, my_bases, await_ack=True)
        bases_a = their_bases
        bases_b = my_bases

    # Step 2: Sift key and categorize test cases for CHSH
    chsh_bins = {
        (0, 0): [], (0, 1): [],
        (1, 0): [], (1, 1): []
    }

    alice_map = {0: 0, np.pi / 4: 1}
    bob_map = {np.pi / 4: 0, np.pi / 2: 1}

    for i in range(min(len(bases_a), len(bases_b))):
        try:
            a_idx = alice_map[bases_a[i]]
            b_idx = bob_map[bases_b[i]]
            chsh_bins[(a_idx, b_idx)].append(i)
        except KeyError:
            continue

    sifted_key_indices = chsh_bins[(1, 0)]

    # Step 3: Exchange measurement outcomes for test qubits
    test_indices = chsh_bins[(0, 0)] + chsh_bins[(0, 1)] + chsh_bins[(1, 1)]
    my_test_meas = {i: my_meas[i] for i in test_indices}
    if is_initiator:
        host.send_classical(partner_id, my_test_meas, await_ack=True)
        their_test_meas_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_test_meas_obj is None:
            return None
        their_test_meas = their_test_meas_obj.content
        test_meas_a = my_test_meas
        test_meas_b = their_test_meas
    else:
        their_test_meas_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if their_test_meas_obj is None:
            return None
        their_test_meas = their_test_meas_obj.content
        host.send_classical(partner_id, my_test_meas, await_ack=True)
        test_meas_a = their_test_meas
        test_meas_b = my_test_meas

    # Step 4: Perform CHSH Test
    E = {}
    for a_idx, b_idx in chsh_bins:
        indices = chsh_bins[(a_idx, b_idx)]
        if not indices:
            E[(a_idx, b_idx)] = 0
            continue

        # Use the publicly revealed test measurements for the calculation
        num_same = sum(1 for i in indices if (test_meas_a.get(i) == test_meas_b.get(i)))
        num_diff = len(indices) - num_same
        E[(a_idx, b_idx)] = (num_same - num_diff) / len(indices)

    S = E[(0, 0)] - E[(0, 1)] + E[(1, 0)] + E[(1, 1)]
    print(f"[{host.host_id}] CHSH S-value: {S:.4f} (Classical limit is 2, Quantum max is {2 * np.sqrt(2):.4f})")

    if abs(S) > 2.0:
        print(f"[{host.host_id}] Bell test PASSED. Entanglement confirmed.")
        # Key is constructed from the measurements that were kept secret
        final_key = "".join([str(my_meas[i]) for i in sifted_key_indices])
        return final_key
    else:
        print(f"[{host.host_id}] Bell test FAILED. No quantum advantage detected.")
        return None


def e91_sender_protocol(host: Host, receiver_id: Host.host_id, message: str):
    message_binary = ''.join(format(byte, '08b') for byte in message.encode())
    required_key_len = len(message_binary)
    num_pairs = ceil(required_key_len * QKD_QUBIT_RATIO)

    host.send_classical(receiver_id, str(num_pairs), await_ack=True)
    print(f"[{host.host_id}] Establishing {num_pairs} EPR pairs with [{receiver_id}].")

    epr_ids = []
    for i in range(num_pairs):
        epr_id, _ = host.send_epr(receiver_id, await_ack=True)
        epr_ids.append(epr_id)

    bases_a = [random.choice([0, np.pi / 4]) for _ in range(num_pairs)]
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


def e91_receiver_protocol(host: Host, sender_id: Host.host_id):
    msg = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if msg is None: return None
    num_pairs = int(msg.content)
    print(f"[{host.host_id}] Awaiting {num_pairs} EPR pairs from [{sender_id}].")

    bases_b = [random.choice([np.pi / 4, np.pi / 2]) for _ in range(num_pairs)]
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


# #############################################################################
# Middleware Protocols
# #############################################################################

def middleware_classical_to_quantum(host: Host, classical_id: Host.host_id, quantum_id: Host.host_id, pqc_protocol,
                                    qkd_sender_protocol):
    message = classical_receiver_protocol(host, classical_id, pqc_protocol)
    if message:
        qkd_sender_protocol(host, quantum_id, message)


def middleware_quantum_to_classical(host: Host, classical_id: Host.host_id, quantum_id: Host.host_id, pqc_protocol,
                                    qkd_receiver_protocol):
    message = qkd_receiver_protocol(host, quantum_id)
    if message:
        classical_sender_protocol(host, classical_id, message, pqc_protocol)


def setup_network():
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

    hosts = [host_classical, host_middleware, host_quantum]

    network.add_hosts(hosts)

    return network, hosts


def simulate_network(pqc_protocol, qkd_protocol, message, classical_is_sender):
    network, hosts = setup_network()

    host_classical, host_middleware, host_quantum = hosts

    qkd_protocol_name, qkd_sender_protocol, qkd_receiver_protocol = qkd_protocol

    print(f"## Running full simulation with PQC:{type(pqc_protocol).__name__} and QKD:{qkd_protocol_name} ##")

    if classical_is_sender:
        thread1 = host_classical.run_protocol(classical_sender_protocol,
                                              (host_middleware.host_id, message, pqc_protocol))
        thread2 = host_middleware.run_protocol(middleware_classical_to_quantum,
                                               (host_classical.host_id, host_quantum.host_id, pqc_protocol,
                                                qkd_sender_protocol))
        thread3 = host_quantum.run_protocol(qkd_receiver_protocol, (host_middleware.host_id,))
    else:
        thread1 = host_quantum.run_protocol(qkd_sender_protocol, (host_middleware.host_id, message))
        thread2 = host_middleware.run_protocol(middleware_quantum_to_classical,
                                               (host_classical.host_id, host_quantum.host_id, pqc_protocol,
                                                qkd_receiver_protocol))
        thread3 = host_classical.run_protocol(classical_receiver_protocol, (host_middleware.host_id, pqc_protocol))

    thread1.join()
    thread2.join()
    thread3.join()

    network.stop()


def main():
    pqc_protocol = MLKEM_1024()

    qkd_protocols = {
        1: ("B92", b92_sender_protocol, b92_receiver_protocol),
        2: ("E91", e91_sender_protocol, e91_receiver_protocol)
    }

    # Choose the QKD protocol by setting the number below.
    qkd_protocol_choice = 2

    try:
        qkd_protocol = qkd_protocols[qkd_protocol_choice]
    except KeyError:
        print(f"ERROR: Invalid qkd_protocol_choice '{qkd_protocol_choice}'.")
        return

    message = "He"

    simulate_network(pqc_protocol, qkd_protocol, message, classical_is_sender=True)


if __name__ == '__main__':
    main()
