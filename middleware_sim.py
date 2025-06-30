import base64
import hashlib
import random
from math import ceil
import numpy as np
from cryptography.fernet import Fernet
from quantcrypt.kem import MLKEM_1024
from qunetsim.components import Host, Network
from qunetsim.objects import Logger, Qubit

# #############################################################################
# Global Constants
# #############################################################################

Logger.DISABLED = False
NETWORK_TIMEOUT = 20
QKD_CHECK_RATIO = 0.5
QKD_QUBIT_RATIO = 5.0
MESSAGE_ENCODING = 'utf-8'


# #############################################################################
# Utility Functions
# #############################################################################

def apply_one_time_pad(binary_input: str, key: str) -> str:
    """
    Encrypts or decrypts a binary string using a one-time pad key.
    """
    if len(key) < len(binary_input):
        raise ValueError("One-Time Pad key cannot be shorter than the message.")
    input_int = int(binary_input, 2)
    key_int = int(key[:len(binary_input)], 2)
    result_int = input_int ^ key_int
    return format(result_int, f'0{len(binary_input)}b')


def binary_to_text(binary_string: str) -> str:
    """
    Converts a binary string back into a human-readable text string.
    """
    byte_chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    byte_list = [int(chunk, 2) for chunk in byte_chunks]
    return bytes(byte_list).decode(MESSAGE_ENCODING, 'ignore')


def text_to_binary(text: str) -> str:
    """
    Converts a text string into a binary string.
    """
    return ''.join(format(byte, '08b') for byte in text.encode(MESSAGE_ENCODING))


def generate_binary_key(length: int) -> str:
    """
    Generates a random binary string of a specified length.
    """
    return ''.join(random.choice('01') for _ in range(length))


def derive_fernet_key(shared_secret: bytes) -> bytes:
    """
    Derives a Fernet-compatible key from a shared secret.
    """
    hashed_secret = hashlib.sha256(shared_secret).digest()
    return base64.urlsafe_b64encode(hashed_secret)


# #############################################################################
# Classical PQC Protocols (ML-KEM)
# #############################################################################

def classical_receiver_protocol(host: Host, sender_id: str, kem_instance):
    """
    Protocol for a classical node to receive a message encrypted with ML-KEM.
    """
    print(f"[{host.host_id}] Generating KEM key pair.")
    public_key, secret_key = kem_instance.keygen()

    print(f"[{host.host_id}] Sending public key to [{sender_id}].")
    host.send_classical(sender_id, public_key, await_ack=True)

    ciphertext_obj = host.get_next_classical(sender_id, wait=-1)
    if not ciphertext_obj:
        print(f"ERROR: [{host.host_id}] Timed out waiting for ciphertext from [{sender_id}].")
        return None
    ciphertext = ciphertext_obj.content
    print(f"[{host.host_id}] Received KEM ciphertext from [{sender_id}].")

    shared_secret = kem_instance.decaps(secret_key, ciphertext)
    fernet_key = derive_fernet_key(shared_secret)
    receiver_fernet = Fernet(fernet_key)

    encrypted_message_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not encrypted_message_obj:
        print(f"ERROR: [{host.host_id}] Timed out waiting for encrypted message from [{sender_id}].")
        return None
    encrypted_message = encrypted_message_obj.content
    print(f"[{host.host_id}] Received Fernet-encrypted message from [{sender_id}].")

    decrypted_message = receiver_fernet.decrypt(encrypted_message).decode(MESSAGE_ENCODING)
    print(f"[{host.host_id}] Successfully decrypted classical message: '{decrypted_message}'")
    return decrypted_message


def classical_sender_protocol(host: Host, receiver_id: str, message: str, kem_instance):
    """
    Protocol for a classical node to send a message encrypted with ML-KEM.
    """
    public_key_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if not public_key_obj:
        print(f"ERROR: [{host.host_id}] Timed out waiting for public key from [{receiver_id}].")
        return
    public_key = public_key_obj.content
    print(f"[{host.host_id}] Received public key from [{receiver_id}].")

    print(f"[{host.host_id}] Generating KEM ciphertext and shared secret.")
    ciphertext, shared_secret = kem_instance.encaps(public_key)

    print(f"[{host.host_id}] Sending KEM ciphertext to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext, await_ack=True)

    fernet_key = derive_fernet_key(shared_secret)
    sender_fernet = Fernet(fernet_key)

    encrypted_message = sender_fernet.encrypt(message.encode(MESSAGE_ENCODING))
    print(f"[{host.host_id}] Sending Fernet-encrypted message to [{receiver_id}].")
    host.send_classical(receiver_id, encrypted_message, await_ack=True)


# #############################################################################
# B92 QKD Protocol Components
# #############################################################################

def b92_send_qubits(alice: Host, secret_key: str, bob_id: str):
    """
    Alice's part of the B92 QKD protocol: sends qubits based on her secret key.
    """
    sent_qubit_counter = 0
    for bit in secret_key:
        is_ack_received = False
        while not is_ack_received:
            qubit = Qubit(alice)
            if bit == '1':
                qubit.H()  # Send |+> for a '1'
            # For '0', send |0> (no operation needed after initialization)

            alice.send_qubit(bob_id, qubit, await_ack=True)
            ack = alice.get_next_classical(bob_id, wait=NETWORK_TIMEOUT)

            if ack and ack.content == 'qubit successfully acquired':
                print(f"[{alice.host_id}] ACK for qubit {sent_qubit_counter + 1} received.")
                is_ack_received = True
                sent_qubit_counter += 1
            else:
                print(f"[{alice.host_id}] ACK not received for qubit {sent_qubit_counter + 1}. Resending.")


def b92_receive_qubits(bob: Host, key_size: int, alice_id: str) -> str:
    """
    Bob's part of the B92 QKD protocol: receives and measures qubits.
    """
    key_bob = []
    received_count = 0
    while received_count < key_size:
        basis = random.randint(0, 1)  # 0 for Z-basis, 1 for X-basis
        qubit = bob.get_qubit(alice_id, wait=NETWORK_TIMEOUT)

        if qubit:
            if basis == 1:  # X-basis measurement
                qubit.H()

            bit = qubit.measure()

            if bit == 1:
                # If measurement is 1, Bob knows Alice's bit.
                resulting_key_bit = '0' if basis == 1 else '1'
                key_bob.append(resulting_key_bit)
                bob.send_classical(alice_id, 'qubit successfully acquired', await_ack=True)
                received_count += 1
                print(f"[{bob.host_id}] Successfully measured qubit {received_count}/{key_size}.")
            else:
                # Measurement is 0, Bob cannot determine the bit, requests resend.
                bob.send_classical(alice_id, 'fail', await_ack=True)
    return "".join(key_bob)


def b92_verify_key(host: Host, partner_id: str, key_to_check: str, is_initiator: bool) -> bool:
    """
    A generic key verification process for QKD.
    """
    if is_initiator:
        print(f"[{host.host_id}] Sending key portion for verification: {key_to_check}")
        host.send_classical(partner_id, key_to_check, await_ack=True)
        response = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if response and response.content == 'Success':
            print(f"[{host.host_id}] Key verification successful.")
            return True
        else:
            print(f"[{host.host_id}] Key verification failed.")
            return False
    else:
        key_from_partner = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if key_from_partner and key_from_partner.content == key_to_check:
            print(f"[{host.host_id}] Received key portion matches. Sending success.")
            host.send_classical(partner_id, 'Success', await_ack=True)
            return True
        else:
            print(f"[{host.host_id}] Received key portion does not match. Sending failure.")
            host.send_classical(partner_id, 'Fail', await_ack=True)
            return False


# #############################################################################
# B92 QKD Protocols
# #############################################################################

def b92_sender_protocol(host: Host, receiver_id: str, message: str):
    """
    Full B92 QKD sender protocol.
    """
    message_binary = text_to_binary(message)
    key_check_length = ceil(len(message_binary) * QKD_CHECK_RATIO)
    total_key_length = len(message_binary) + key_check_length

    key_info_message = f"KEY_INFO:{total_key_length}:{key_check_length}"
    print(f"[{host.host_id}] Announcing QKD parameters to [{receiver_id}].")
    host.send_classical(receiver_id, key_info_message, await_ack=True)

    full_key = generate_binary_key(total_key_length)
    b92_send_qubits(host, full_key, receiver_id)
    print(f"[{host.host_id}] All QKD qubits sent to [{receiver_id}].")

    key_to_verify = full_key[:key_check_length]
    if not b92_verify_key(host, receiver_id, key_to_verify, is_initiator=True):
        print(f"CRITICAL: [{host.host_id}] Protocol aborted due to key check failure.")
        return

    one_time_pad_key = full_key[key_check_length:]
    ciphertext_binary = apply_one_time_pad(message_binary, one_time_pad_key)

    print(f"[{host.host_id}] Encrypted message with one-time pad, sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext_binary, await_ack=True)


def b92_receiver_protocol(host: Host, sender_id: str):
    """
    Full B92 QKD receiver protocol.
    """
    key_info_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)

    if not key_info_obj:
        print(f"ERROR: [{host.host_id}] Timed out waiting for key info from [{sender_id}].")
        return None
    elif not key_info_obj.content.startswith("KEY_INFO:"):
        print(f"ERROR: [{host.host_id}] Timed out or received invalid key info from [{sender_id}].")
        return None

    _, key_length_str, key_check_length_str = key_info_obj.content.split(':')
    key_length = int(key_length_str)
    key_check_length = int(key_check_length_str)
    print(f"[{host.host_id}] Received QKD parameters from [{sender_id}].")

    full_key = b92_receive_qubits(host, key_length, sender_id)
    key_to_verify = full_key[:key_check_length]

    if not b92_verify_key(host, sender_id, key_to_verify, is_initiator=False):
        print(f"CRITICAL: [{host.host_id}] Protocol aborted due to key check failure.")
        return None

    encrypted_message = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not encrypted_message:
        print(f"[{host.host_id}] Timed out waiting for final message. Sender may have aborted.")
        return None

    one_time_pad_key = full_key[key_check_length:]
    decrypted_binary = apply_one_time_pad(encrypted_message.content, one_time_pad_key)
    decrypted_message = binary_to_text(decrypted_binary)

    print(f"[{host.host_id}] Successfully decrypted quantum message: '{decrypted_message}'")
    return decrypted_message


# #############################################################################
# E91 QKD Protocol Components
# #############################################################################

def e91_exchange_bases(host: Host, partner_id: str, local_bases: list, is_initiator: bool):
    """
    Exchanges measurement bases between two parties.
    """
    if is_initiator:
        host.send_classical(partner_id, local_bases, await_ack=True)
        remote_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        return local_bases, remote_bases_obj.content if remote_bases_obj else None
    else:
        remote_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
        if not remote_bases_obj: return None, None
        host.send_classical(partner_id, local_bases, await_ack=True)
        return remote_bases_obj.content, local_bases


def e91_perform_chsh_test(alice_bases, bob_bases, alice_meas, bob_meas):
    """
    Calculates the CHSH S-value to test for entanglement.
    """
    # Define basis mappings for CHSH inequality
    # Alice's bases: 0 (a1), pi/4 (a2)
    # Bob's bases:   pi/4 (b1), pi/2 (b2)
    alice_map = {0: 0, np.pi / 4: 1}
    bob_map = {np.pi / 4: 0, np.pi / 2: 1}

    # Correlators E(a,b)
    E = {}
    for a_idx, b_idx in [(0, 0), (0, 1), (1, 0), (1, 1)]:
        num_same, num_diff = 0, 0
        for i in range(len(alice_bases)):
            try:
                if alice_map[alice_bases[i]] == a_idx and bob_map[bob_bases[i]] == b_idx:
                    if alice_meas[i] == bob_meas[i]:
                        num_same += 1
                    else:
                        num_diff += 1
            except KeyError:
                continue  # Basis not used in this correlator
        total = num_same + num_diff
        E[(a_idx, b_idx)] = (num_same - num_diff) / total if total > 0 else 0

    # S = E(a1,b1) - E(a1,b2) + E(a2,b1) + E(a2,b2)
    s_value = E.get((0, 0), 0) - E.get((0, 1), 0) + E.get((1, 0), 0) + E.get((1, 1), 0)
    return s_value


def e91_extract_key(local_bases, partner_bases, local_measurements):
    """
    Sifts the raw measurements to form the final key based on basis agreement.
    The key is generated when Alice uses a2 (pi/4) and Bob uses b1 (pi/4).
    """
    sifted_key = ""
    for i in range(len(local_bases)):
        if local_bases[i] == np.pi / 4 and partner_bases[i] == np.pi / 4:
            sifted_key += str(local_measurements[i])
    return sifted_key


# #############################################################################
# E91 QKD Protocols
# #############################################################################

def e91_sender_protocol(host: Host, receiver_id: str, message: str):
    """
    Full E91 QKD sender (Alice) protocol.
    """
    message_binary = text_to_binary(message)
    required_key_len = len(message_binary)
    num_pairs = ceil(required_key_len * QKD_QUBIT_RATIO)

    host.send_classical(receiver_id, str(num_pairs), await_ack=True)
    print(f"[{host.host_id}] Establishing {num_pairs} EPR pairs with [{receiver_id}].")

    # Step 1: Create and send all EPR pairs, storing their IDs
    epr_ids = []
    for i in range(num_pairs):
        epr_id, ack_received = host.send_epr(receiver_id, await_ack=True)
        if ack_received:
            epr_ids.append(epr_id)
        else:
            # Handle the case where the pair creation wasn't acknowledged
            print(f"WARN: [{host.host_id}] Failed to get ACK for EPR pair {i + 1}, it will be skipped.")

    # Abort if we couldn't create enough pairs
    if len(epr_ids) < num_pairs:
        print(f"CRITICAL: [{host.host_id}] Failed to establish enough EPR pairs. Aborting.")
        host.send_classical(receiver_id, "ABORT", await_ack=True)
        return

    # Step 2: Now retrieve the local qubits by ID and measure them
    bases_a = [random.choice([0, np.pi / 4]) for _ in range(num_pairs)]
    meas_a = []
    for i in range(num_pairs):
        q = host.get_epr(receiver_id, epr_ids[i])
        if q:
            q.ry(bases_a[i])  # Apply rotation for measurement basis
            meas_a.append(q.measure())
        else:
            print(f"WARN: [{host.host_id}] Could not retrieve local EPR qubit for ID {epr_ids[i]}.")

    # Exchange bases with Bob
    _, bases_b = e91_exchange_bases(host, receiver_id, bases_a, is_initiator=True)
    if bases_b is None:
        print(f"CRITICAL: [{host.host_id}] Failed to exchange bases with [{receiver_id}].")
        return

    # Exchange measurement outcomes with Bob
    host.send_classical(receiver_id, meas_a, await_ack=True)
    meas_b_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if not meas_b_obj:
        print(f"CRITICAL: [{host.host_id}] Timed out waiting for partner's measurements.")
        return
    meas_b = meas_b_obj.content

    # Perform Bell Test with both sets of measurements
    s_value = e91_perform_chsh_test(bases_a, bases_b, meas_a, meas_b)
    print(f"[{host.host_id}] Calculated CHSH S-value: {s_value:.4f}")

    if abs(s_value) <= 2.0:
        print(f"CRITICAL: [{host.host_id}] Bell test FAILED. Aborting protocol.")
        return

    print(f"[{host.host_id}] Bell test PASSED. Entanglement confirmed.")
    one_time_pad_key = e91_extract_key(bases_a, bases_b, meas_a)

    if len(one_time_pad_key) < required_key_len:
        print(f"CRITICAL: [{host.host_id}] Generated key too short. Aborting.")
        return

    # Encrypt and send message
    ciphertext_binary = apply_one_time_pad(message_binary, one_time_pad_key)
    print(f"[{host.host_id}] Encrypted message with OTP, sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext_binary, await_ack=True)


def e91_receiver_protocol(host: Host, sender_id: str):
    """
    Full E91 QKD receiver (Bob) protocol.
    """
    msg = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not msg:
        print(f"ERROR: [{host.host_id}] Did not receive pair count from [{sender_id}].")
        return None
    num_pairs = int(msg.content)
    print(f"[{host.host_id}] Awaiting {num_pairs} EPR pairs from [{sender_id}].")

    # Measure EPR pairs
    bases_b = [random.choice([np.pi / 4, np.pi / 2]) for _ in range(num_pairs)]
    meas_b = []
    for _ in range(num_pairs):
        q = host.get_epr(sender_id, wait=NETWORK_TIMEOUT)
        if q:
            basis = bases_b[len(meas_b)]
            q.ry(basis)
            meas_b.append(q.measure())

    # Exchange bases with Alice
    bases_a, _ = e91_exchange_bases(host, sender_id, bases_b, is_initiator=False)
    if bases_a is None:
        print(f"CRITICAL: [{host.host_id}] Failed to exchange bases with [{sender_id}].")
        return None

    # Exchange measurement outcomes with Alice
    meas_a_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not meas_a_obj:
        print(f"CRITICAL: [{host.host_id}] Timed out waiting for partner's measurements.")
        return None
    meas_a = meas_a_obj.content
    host.send_classical(sender_id, meas_b, await_ack=True)

    # Perform Bell Test with both sets of measurements
    s_value = e91_perform_chsh_test(bases_a, bases_b, meas_a, meas_b)
    print(f"[{host.host_id}] Calculated CHSH S-value: {s_value:.4f}")

    if abs(s_value) <= 2.0:
        print(f"CRITICAL: [{host.host_id}] Bell test FAILED. Aborting protocol.")
        return None

    print(f"[{host.host_id}] Bell test PASSED. Entanglement confirmed.")
    one_time_pad_key = e91_extract_key(bases_b, bases_a, meas_b)

    # Receive and decrypt message
    encrypted_message = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not encrypted_message:
        print(f"[{host.host_id}] Timed out waiting for final message.")
        return None

    decrypted_binary = apply_one_time_pad(encrypted_message.content, one_time_pad_key)
    decrypted_message = binary_to_text(decrypted_binary)

    print(f"[{host.host_id}] Successfully decrypted quantum message: '{decrypted_message}'")
    return decrypted_message


# #############################################################################
# Middleware Protocols
# #############################################################################

def middleware_classical_to_quantum(host: Host, classical_id: str, quantum_id: str,
                                    pqc_kem, qkd_sender_protocol):
    """
    Middleware to receive a classical message and forward it over a quantum channel.
    """
    message = classical_receiver_protocol(host, classical_id, pqc_kem)
    if message:
        qkd_sender_protocol(host, quantum_id, message)


def middleware_quantum_to_classical(host: Host, quantum_id: str, classical_id: str,
                                    pqc_kem, qkd_receiver_protocol):
    """
    Middleware to receive a quantum message and forward it over a classical channel.
    """
    message = qkd_receiver_protocol(host, quantum_id)
    if message:
        classical_sender_protocol(host, classical_id, message, pqc_kem)


# #############################################################################
# Simulation Setup and Execution
# #############################################################################

def setup_network():
    """
    Initializes and connects the hosts in the network.
    """
    network = Network.get_instance()
    network.start()

    hosts = {
        'classical': Host('Classical Node'),
        'middleware': Host('Middleware Node'),
        'quantum': Host('Quantum Node')
    }

    hosts['classical'].add_c_connection(hosts['middleware'].host_id)
    hosts['middleware'].add_c_connection(hosts['classical'].host_id)
    hosts['middleware'].add_connection(hosts['quantum'].host_id)
    hosts['quantum'].add_connection(hosts['middleware'].host_id)

    for host in hosts.values():
        host.start()

    network.add_hosts(list(hosts.values()))
    return network, hosts


def run_simulation(pqc_kem, qkd_protocol, message, classical_is_sender):
    """
    Runs the full network simulation for a given scenario.
    """
    network, hosts = setup_network()
    qkd_name, qkd_sender, qkd_receiver = qkd_protocol

    print(
        f"\n## Running Simulation: PQC={type(pqc_kem).__name__}, QKD={qkd_name}, Direction={'C->Q' if classical_is_sender else 'Q->C'} ##")

    classical_node = hosts['classical']
    middleware_node = hosts['middleware']
    quantum_node = hosts['quantum']

    if classical_is_sender:
        thread1 = classical_node.run_protocol(classical_sender_protocol,
                                              (middleware_node.host_id, message, pqc_kem))
        thread2 = middleware_node.run_protocol(middleware_classical_to_quantum,
                                               (classical_node.host_id, quantum_node.host_id, pqc_kem, qkd_sender))
        thread3 = quantum_node.run_protocol(qkd_receiver, (middleware_node.host_id,))
    else:
        thread1 = quantum_node.run_protocol(qkd_sender, (middleware_node.host_id, message))
        thread2 = middleware_node.run_protocol(middleware_quantum_to_classical,
                                               (quantum_node.host_id, classical_node.host_id, pqc_kem, qkd_receiver))
        thread3 = classical_node.run_protocol(classical_receiver_protocol, (middleware_node.host_id, pqc_kem))

    for thread in [thread1, thread2, thread3]:
        thread.join()

    network.stop()


def main():
    """
    Main function to define and run the simulation scenarios.
    """
    pqc_kem_instance = MLKEM_1024()
    message = "Hello World!"

    qkd_protocols = {
        "B92": ("B92", b92_sender_protocol, b92_receiver_protocol),
        "E91": ("E91", e91_sender_protocol, e91_receiver_protocol)
    }

    # --- Scenario 1: Classical to Quantum with B92 ---
    run_simulation(
        pqc_kem=pqc_kem_instance,
        qkd_protocol=qkd_protocols["B92"],
        message=message,
        classical_is_sender=True
    )

    # --- Scenario 2: Quantum to Classical with B92 ---
    run_simulation(
        pqc_kem=pqc_kem_instance,
        qkd_protocol=qkd_protocols["B92"],
        message=message,
        classical_is_sender=False
    )

    # --- Scenario 3: Classical to Quantum with E91 ---
    run_simulation(
        pqc_kem=pqc_kem_instance,
        qkd_protocol=qkd_protocols["E91"],
        message=message,
        classical_is_sender=True
    )

    # --- Scenario 4: Quantum to Classical with E91 ---
    run_simulation(
        pqc_kem=pqc_kem_instance,
        qkd_protocol=qkd_protocols["E91"],
        message=message,
        classical_is_sender=False
    )


if __name__ == '__main__':
    main()
