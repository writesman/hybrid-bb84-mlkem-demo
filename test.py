import random
import numpy as np
import hashlib
import base64
from math import ceil, sqrt
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger
from quantcrypt.kem import MLKEM_1024
from cryptography.fernet import Fernet

# --- Configuration Constants ---
# Set to True to see QuNetSim logs, False to hide them
Logger.DISABLED = True
# Network timeout in seconds. E91 can be slow, so a high value is recommended.
NETWORK_TIMEOUT = 180

# --- Constants for the BB84-like Protocol ---
# Ratio of the key to use for checking against eavesdropping
BB84_CHECK_RATIO = 0.5

# --- Constants for the E91 Protocol ---
# Ratio of EPR pairs to generate relative to the required key length.
# A higher ratio means more pairs for the Bell test, but a slower simulation.
E91_QUBIT_RATIO = 5.0
# The theoretical maximum S-value for the CHSH inequality in a quantum system
CHSH_QUANTUM_MAX = 2 * sqrt(2)


# #############################################################################
# SECTION 1: COMMON UTILITY AND CLASSICAL PROTOCOL FUNCTIONS
# These functions are used by both QKD protocol implementations.
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
    return bytes(byte_list).decode('utf-8', 'ignore')


def classical_sender_protocol(host: Host, receiver_id: str, message: str, kem):
    """
    Protocol for the classical node to send an encrypted message to the middleware.
    This uses post-quantum cryptography (ML-KEM) for key exchange.
    """
    print(f"[{host.host_id}] waiting for public key from [{receiver_id}].")
    public_key_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if public_key_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for public key.")
        return
    public_key = public_key_obj.content
    print(f"[{host.host_id}] Received public key.")

    ciphertext, shared_secret = kem.encaps(public_key)
    print(f"[{host.host_id}] Generated KEM ciphertext and sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext, await_ack=True)

    raw_key = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(raw_key)
    sender_fernet = Fernet(fernet_key)

    encrypted_message = sender_fernet.encrypt(message.encode())
    print(f"[{host.host_id}] Sending Fernet-encrypted message: '{message}'")
    host.send_classical(receiver_id, encrypted_message, await_ack=True)


def classical_receiver_protocol(host: Host, sender_id: str, kem):
    """
    Protocol for the classical node to receive an encrypted message from the middleware.
    """
    print(f"[{host.host_id}] Generating KEM key pair.")
    public_key, secret_key = kem.keygen()

    print(f"[{host.host_id}] Sending public key to [{sender_id}].")
    host.send_classical(sender_id, public_key, await_ack=True)

    ciphertext_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if ciphertext_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for ciphertext.")
        return None
    ciphertext = ciphertext_obj.content
    print(f"[{host.host_id}] Received KEM ciphertext.")

    shared_secret = kem.decaps(secret_key, ciphertext)

    raw_key = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(raw_key)
    receiver_fernet = Fernet(fernet_key)

    encrypted_message_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if encrypted_message_obj is None:
        print(f"ERROR: [{host.host_id}] timed out waiting for encrypted message.")
        return None
    encrypted_message = encrypted_message_obj.content
    print(f"[{host.host_id}] Received Fernet-encrypted message.")

    decrypted_message = receiver_fernet.decrypt(encrypted_message).decode()
    print(f"[{host.host_id}] Successfully decrypted classical message: '{decrypted_message}'")
    return decrypted_message


# #############################################################################
# SECTION 2: BB84-LIKE QKD PROTOCOL
# The following functions implement the first QKD protocol provided.
# #############################################################################

def bb84_generate_key(key_length):
    """Generates a random binary key of a given length."""
    return [random.randint(0, 1) for _ in range(key_length)]


def bb84_sender_qkd(alice: Host, secret_key: list, receiver_id: str):
    """Sends qubits based on the secret key bits."""
    for i, bit in enumerate(secret_key):
        while True:
            qubit = Qubit(alice)
            if bit == 1:
                qubit.H()  # Send |+> for a 1
            # Send |0> for a 0
            alice.send_qubit(receiver_id, qubit, await_ack=True)
            message = alice.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
            if message is not None and message.content == 'qubit successfully acquired':
                print(f"[{alice.host_id}] Qubit {i + 1}/{len(secret_key)} acknowledged by [{receiver_id}].")
                break
            else:
                print(f"[{alice.host_id}] Timeout/Fail on qubit {i + 1}. Resending.")


def bb84_receiver_qkd(bob: Host, key_size: int, sender_id: str):
    """Receives qubits and measures them in a random basis."""
    key_array = []
    received_counter = 0
    while received_counter < key_size:
        basis = random.randint(0, 1)  # 0 for Z-basis, 1 for X-basis
        qubit = bob.get_qubit(sender_id, wait=NETWORK_TIMEOUT)
        if qubit is not None:
            if basis == 1:
                qubit.H()

            # This logic seems to have a mistake from the original.
            # Measuring 1 in Z-basis means the key bit was 1.
            # Measuring 1 in X-basis means original was |->, which isn't sent.
            # We will follow the logic as provided.
            bit = qubit.measure()
            if bit == 1:
                key_array.append(1 if basis == 0 else 0)
                msg_to_send = 'qubit successfully acquired'
                received_counter += 1
                print(f"[{bob.host_id}] Qubit {received_counter}/{key_size} successfully measured.")
            else:
                msg_to_send = 'fail'  # This case is not ideal as it leaks info
            bob.send_classical(sender_id, msg_to_send, await_ack=True)
    return key_array


def bb84_check_key_sender(alice: Host, key_check: list, receiver_id: str):
    """Sender sends a portion of the key to the receiver for verification."""
    key_check_string = ''.join([str(x) for x in key_check])
    print(f"[{alice.host_id}] Sending check key to [{receiver_id}].")
    alice.send_classical(receiver_id, key_check_string, await_ack=True)
    message = alice.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if message and message.content == 'Success':
        print(f"[{alice.host_id}] Key verification successful!")
        return True
    else:
        print(f"[{alice.host_id}] KEY MISMATCH or timeout. Aborting.")
        return False


def bb84_check_key_receiver(bob: Host, key_check: list, sender_id: str):
    """Receiver compares its check key with the one from the sender."""
    key_check_bob_string = ''.join([str(x) for x in key_check])
    key_from_alice_obj = bob.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not key_from_alice_obj:
        print(f"[{bob.host_id}] Timed out waiting for key check from [{sender_id}].")
        return

    if key_from_alice_obj.content == key_check_bob_string:
        print(f"[{bob.host_id}] Keys match. Sending success message.")
        bob.send_classical(sender_id, 'Success', await_ack=True)
    else:
        print(f"[{bob.host_id}] Keys DO NOT match. Sending fail message.")
        bob.send_classical(sender_id, 'Fail', await_ack=True)


def b92_sender_protocol(host: Host, receiver_id: str, message: str):
    """Full quantum sender protocol using the BB84-like method."""
    print(f"\n--- Initiating BB84-like QKD for Sender [{host.host_id}] ---")
    message_binary = ''.join(format(byte, '08b') for byte in message.encode())
    key_check_length = ceil(len(message_binary) * BB84_CHECK_RATIO)
    key_length = len(message_binary) + key_check_length

    host.send_classical(receiver_id, f"KEY_INFO:{key_length}:{key_check_length}", await_ack=True)

    encryption_key = bb84_generate_key(key_length)
    bb84_sender_qkd(host, encryption_key, receiver_id)

    key_to_test = encryption_key[:key_check_length]
    if not bb84_check_key_sender(host, key_to_test, receiver_id):
        return

    one_time_pad_key = ''.join(map(str, encryption_key[key_check_length:]))
    ciphertext = apply_one_time_pad(message_binary, one_time_pad_key)

    print(f"[{host.host_id}] Encrypted message with OTP, sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext, await_ack=True)


def b92_receiver_protocol(host: Host, sender_id: str):
    """Full quantum receiver protocol using the BB84-like method."""
    print(f"\n--- Initiating BB84-like QKD for Receiver [{host.host_id}] ---")
    key_info_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not key_info_obj or not key_info_obj.content.startswith("KEY_INFO:"):
        print(f"ERROR: [{host.host_id}] Invalid or no key info received.")
        return None

    _, key_length, key_check_length = key_info_obj.content.split(':')
    key_length, key_check_length = int(key_length), int(key_check_length)

    secret_key = bb84_receiver_qkd(host, key_length, sender_id)
    key_to_test = secret_key[:key_check_length]
    bb84_check_key_receiver(host, key_to_test, sender_id)

    encrypted_message = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if encrypted_message is None:
        print(f"[{host.host_id}] Timeout: Sender may have aborted.")
        return None

    one_time_pad_key = ''.join(map(str, secret_key[key_check_length:]))
    decrypted_binary = apply_one_time_pad(encrypted_message.content, one_time_pad_key)
    decrypted_message = binary_to_text(decrypted_binary)

    print(f"[{host.host_id}] Successfully decrypted quantum message: '{decrypted_message}'")
    return decrypted_message


# #############################################################################
# SECTION 3: E91 (EKERT) QKD PROTOCOL
# The following functions implement the E91 protocol.
# #############################################################################

def e91_sift_and_test(host: Host, partner_id: str, my_bases: list, my_meas: list, is_initiator: bool):
    """
    Performs basis reconciliation, CHSH Bell test, and key sifting for E91.
    """
    # Step 1: Exchange bases
    host.send_classical(partner_id, my_bases, await_ack=True)
    their_bases_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
    if their_bases_obj is None: return None
    their_bases = their_bases_obj.content

    bases_a, bases_b = (my_bases, their_bases) if is_initiator else (their_bases, my_bases)

    # Step 2: Sift key and categorize test cases for CHSH
    # Alice's bases: 0 (A1), pi/4 (A2)
    # Bob's bases:   pi/4 (B1), pi/2 (B2)
    sift_indices, test_indices = [], []
    test_bins = {(0, np.pi / 4): [], (0, np.pi / 2): [], (np.pi / 4, np.pi / 4): [], (np.pi / 4, np.pi / 2): []}

    for i in range(min(len(bases_a), len(bases_b))):
        # A1, B1 -> Test | A2, B2 -> Test
        if (bases_a[i] == 0 and bases_b[i] == np.pi / 4) or \
                (bases_a[i] == np.pi / 4 and bases_b[i] == np.pi / 2):
            test_indices.append(i)
        # A2, B1 -> Sifted Key
        elif bases_a[i] == np.pi / 4 and bases_b[i] == np.pi / 4:
            sift_indices.append(i)
        # A1, B2 -> Test
        elif bases_a[i] == 0 and bases_b[i] == np.pi / 2:
            test_indices.append(i)

    # Step 3: Exchange measurement outcomes for test qubits
    my_test_meas = {i: my_meas[i] for i in test_indices}
    host.send_classical(partner_id, my_test_meas, await_ack=True)
    their_test_meas_obj = host.get_next_classical(partner_id, wait=NETWORK_TIMEOUT)
    if their_test_meas_obj is None: return None
    their_test_meas = their_test_meas_obj.content

    test_meas_a = my_test_meas if is_initiator else their_test_meas
    test_meas_b = their_test_meas if is_initiator else my_test_meas

    # Step 4: Perform CHSH Test
    exp_vals = {}
    for basis_a, basis_b in [(0, np.pi / 4), (np.pi / 4, np.pi / 4), (0, np.pi / 2), (np.pi / 4, np.pi / 2)]:
        num_same, num_diff = 0, 0
        for i in range(len(bases_a)):
            if bases_a[i] == basis_a and bases_b[i] == basis_b and i in test_meas_a and i in test_meas_b:
                if test_meas_a[i] == test_meas_b[i]:
                    num_same += 1
                else:
                    num_diff += 1
        total = num_same + num_diff
        exp_vals[(basis_a, basis_b)] = (num_same - num_diff) / total if total > 0 else 0

    S = exp_vals.get((0, np.pi / 4), 0) + exp_vals.get((np.pi / 4, np.pi / 4), 0) \
        + exp_vals.get((np.pi / 4, np.pi / 2), 0) - exp_vals.get((0, np.pi / 2), 0)

    print(f"[{host.host_id}] CHSH S-value: {S:.4f} (Classical limit is 2, Quantum max is {CHSH_QUANTUM_MAX:.4f})")

    if abs(S) > 2.0:
        print(f"[{host.host_id}] Bell test PASSED. Entanglement confirmed.")
        return "".join([str(my_meas[i]) for i in sift_indices])
    else:
        print(f"[{host.host_id}] Bell test FAILED. Eavesdropper likely. Aborting.")
        return None


def e91_sender_protocol(host: Host, receiver_id: str, message: str):
    """Full quantum sender protocol using the E91 method."""
    print(f"\n--- Initiating E91 QKD for Sender [{host.host_id}] ---")
    message_binary = ''.join(format(byte, '08b') for byte in message.encode())
    num_pairs = ceil(len(message_binary) * E91_QUBIT_RATIO)

    host.send_classical(receiver_id, str(num_pairs), await_ack=True)
    print(f"[{host.host_id}] Establishing {num_pairs} EPR pairs with [{receiver_id}].")

    epr_ids = [host.send_epr(receiver_id, await_ack=True)[0] for _ in range(num_pairs)]

    bases_a = [random.choice([0, np.pi / 4]) for _ in range(num_pairs)]
    meas_a = []
    for i in range(num_pairs):
        q = host.get_epr(receiver_id, epr_ids[i], wait=NETWORK_TIMEOUT)
        if q:
            q.ry(bases_a[i])
            meas_a.append(q.measure())

    one_time_pad_key = e91_sift_and_test(host, receiver_id, bases_a, meas_a, is_initiator=True)

    if not one_time_pad_key or len(one_time_pad_key) < len(message_binary):
        print(f"CRITICAL: [{host.host_id}] Protocol aborted. Key generation failed or key too short.")
        return

    ciphertext = apply_one_time_pad(message_binary, one_time_pad_key)
    print(f"[{host.host_id}] Encrypted message with OTP, sending to [{receiver_id}].")
    host.send_classical(receiver_id, ciphertext, await_ack=True)


def e91_receiver_protocol(host: Host, sender_id: str):
    """Full quantum receiver protocol using the E91 method."""
    print(f"\n--- Initiating E91 QKD for Receiver [{host.host_id}] ---")
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
        print(f"[{host.host_id}] Timeout: Sender may have aborted.")
        return None

    decrypted_binary = apply_one_time_pad(encrypted_message.content, one_time_pad_key)
    decrypted_message = binary_to_text(decrypted_binary)

    print(f"[{host.host_id}] Successfully decrypted quantum message: '{decrypted_message}'")
    return decrypted_message


# #############################################################################
# SECTION 4: MIDDLEWARE, NETWORK SETUP, AND MAIN EXECUTION
# #############################################################################

def middleware_classical_to_quantum(host: Host, classical_id: str, quantum_id: str, kem, quantum_sender_func):
    """Receives classical message and forwards it over the quantum channel."""
    message = classical_receiver_protocol(host, classical_id, kem)
    if message:
        quantum_sender_func(host, quantum_id, message)


def middleware_quantum_to_classical(host: Host, classical_id: str, quantum_id: str, kem, quantum_receiver_func):
    """Receives quantum message and forwards it over the classical channel."""
    message = quantum_receiver_func(host, quantum_id)
    if message:
        classical_sender_protocol(host, classical_id, message, kem)


def setup_network():
    """
    Initializes the network, creates hosts, and sets up connections.
    Returns the three host objects.
    """
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

    return host_classical, host_middleware, host_quantum


def main():
    kem = MLKEM_1024()

    qkd_protocols = {
        1: ("B92", b92_sender_protocol, b92_receiver_protocol),
        2: ("E91", e91_sender_protocol, e91_receiver_protocol)
    }

    # Choose the protocol to run by setting the number below.
    qkd_protocol_choice = 1

    if qkd_protocol_choice not in qkd_protocols:
        print(f"ERROR: Invalid qkd_protocol_choice '{qkd_protocol_choice}'.")
        print(f"Please choose a valid key from: {list(qkd_protocols.keys())}")
        return

    qkd_protocol_name, qkd_sender_protocol, qkd_receiver_protocol = qkd_protocols[qkd_protocol_choice]
    print(f"Running simulation with {qkd_protocol_name} protocol...")

    # --- Network Setup ---
    host_classical, host_middleware, host_quantum = setup_network()

    # --- Simulation 1: Classical-to-Quantum ---
    print("\n#################################################")
    print("## Starting Classical-to-Quantum simulation... ##")
    print("#################################################\n")

    c2q_message = "Hello Quantum World from Classical!"
    thread_c2q_classical = host_classical.run_protocol(
        classical_sender_protocol,
        (host_middleware.host_id, c2q_message, kem)
    )
    thread_c2q_middleware = host_middleware.run_protocol(
        middleware_classical_to_quantum,
        (host_classical.host_id, host_quantum.host_id, kem, q_sender_proto)
    )
    thread_c2q_quantum = host_quantum.run_protocol(
        q_receiver_proto,
        (host_middleware.host_id,)
    )
    thread_c2q_classical.join()
    thread_c2q_middleware.join()
    thread_c2q_quantum.join()
    print("\n## Classical-to-Quantum Simulation Complete ##\n")

    # --- Simulation 2: Quantum-to-Classical ---
    print("\n#################################################")
    print("## Starting Quantum-to-Classical simulation... ##")
    print("#################################################\n")

    q2c_message = "Hello Classical World from Quantum!"
    thread_q2c_quantum = host_quantum.run_protocol(
        q_sender_proto,
        (host_middleware.host_id, q2c_message)
    )
    thread_q2c_middleware = host_middleware.run_protocol(
        middleware_quantum_to_classical,
        (host_classical.host_id, host_quantum.host_id, kem, q_receiver_proto)
    )
    thread_q2c_classical = host_classical.run_protocol(
        classical_receiver_protocol,
        (host_middleware.host_id, kem)
    )
    thread_q2c_quantum.join()
    thread_q2c_middleware.join()
    thread_q2c_classical.join()
    print("\n## Quantum-to-Classical Simulation Complete ##")

    # --- Shutdown ---
    Network.get_instance().stop()


if __name__ == '__main__':
    main()
