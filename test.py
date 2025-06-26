import base64
import hashlib
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit
from qunetsim.objects import Logger


from cryptography.fernet import Fernet

# Constants

Logger.DISABLED = True
NETWORK_TIMEOUT = 20


# Utility functions

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


# Classical Protocols

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


# B92 QKD Protocols

def b92_sender_protocol(alice, secret_key, receiver):
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

def b92_receiver_protocol(bob, key_size, sender):
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

    message = "Hello Quantum World!"

    simulate_network(pqc_protocol, qkd_protocol, message, classical_is_sender=True)


if __name__ == '__main__':
    main()
