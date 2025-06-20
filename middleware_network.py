from qunetsim.components import Host, Network
from quantcrypt.kem import MLKEM_1024
from cryptography.fernet import Fernet
import hashlib
import base64
from b92_protocol import generate_key, sender_qkd, receiver_qkd, check_key_sender, check_key_receiver


def classical_sender_protocol(host: Host, receiver_id: Host.host_id, message, ):
    public_key = host.get_next_classical(receiver_id, wait=-1).content
    print(f"3. {host.host_id}: Received public key from {receiver_id}")

    cipher_text, shared_secret = kem.encaps(public_key)

    print(f"4. {host.host_id}: Sending ciphertext to {receiver_id}")
    host.send_classical(receiver_id, cipher_text, await_ack=True)

    raw_key = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(raw_key)
    sender_fernet = Fernet(fernet_key)

    encrypted_message = sender_fernet.encrypt(message.encode())

    print(f"6. {host.host_id}: Sending encrypted message to {receiver_id}")
    host.send_classical(receiver_id, encrypted_message, await_ack=True)


def classical_receiver_protocol(host: Host, sender_id: Host.host_id, ):
    print(f"1. {host.host_id}: Generating public and secret key.")
    public_key, secret_key = kem.keygen()

    print(f"2. {host.host_id}: Sending public key to {sender_id}.")
    host.send_classical(sender_id, public_key, await_ack=True)

    ciphertext = host.get_next_classical(sender_id, wait=-1).content
    print(f"5. {host.host_id}: Received ciphertext from {sender_id}.")

    shared_secret = kem.decaps(secret_key, ciphertext)

    raw_key = hashlib.sha256(shared_secret).digest()
    fernet_key = base64.urlsafe_b64encode(raw_key)
    receiver_fernet = Fernet(fernet_key)

    encrypted_message = host.get_next_classical(sender_id, wait=-1).content
    print(f"7. {host.host_id}: Received encrypted message from {sender_id}.")

    decrypted_message = receiver_fernet.decrypt(encrypted_message).decode()

    print(f"Decrypted classical message: {decrypted_message}")

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
    # Split the binary string into 8-bit chunks (bytes)
    byte_chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    # Convert each binary chunk into its integer value
    byte_list = [int(chunk, 2) for chunk in byte_chunks]
    # Decode the list of byte values into a string
    return bytes(byte_list).decode('utf-8', 'ignore')


def quantum_sender_protocol(host: Host, receiver_id: Host.host_id, key_length, length_of_check, message_binary, ):
    encryption_key_binary = generate_key(key_length)
    sender_qkd(host, encryption_key_binary, receiver_id)
    print('Sent all the qubits successfully!')
    key_to_test = encryption_key_binary[0:length_of_check]
    check_key_sender(host, key_to_test, receiver_id)

    one_time_pad_key_list = encryption_key_binary[length_of_check:]
    one_time_pad_key_string = ''.join(map(str, one_time_pad_key_list))

    ciphertext_binary = apply_one_time_pad(message_binary, one_time_pad_key_string)

    print(f"encrypted message: {ciphertext_binary} {binary_to_text(ciphertext_binary)}")

    host.send_classical(receiver_id, ciphertext_binary, await_ack=True)


def quantum_receiver_protocol(host: Host, sender_id: Host.host_id, key_length, length_of_check, ):
    secret_key_bob = receiver_qkd(host, key_length, sender_id)
    key_to_test = secret_key_bob[0:length_of_check]
    check_key_receiver(host, key_to_test, sender_id)

    encrypted_message = host.get_next_classical(sender_id)
    if encrypted_message is None:
        print("Bob: Timed out waiting for the final message.")
        return

    ciphertext_binary = encrypted_message.content

    one_time_pad_key_list = secret_key_bob[length_of_check:]

    one_time_pad_key_string = ''.join(map(str, one_time_pad_key_list))

    decrypted_binary = apply_one_time_pad(ciphertext_binary, one_time_pad_key_string)

    decrypted_message = binary_to_text(decrypted_binary)

    print(f'Bob\'s decrypted message is: {decrypted_binary} {decrypted_message}')

    return decrypted_message


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

    message = "Hello World!"

    message_binary = ''.join(format(byte, '08b') for byte in message.encode())
    quantum_key_length = len(message_binary) * 2
    length_of_check = round(quantum_key_length / 2)

    print(f'Quantum key length: {quantum_key_length}')

    # thread_1 = host_quantum.run_protocol(quantum_sender_protocol,
    #                                      (host_middleware.host_id, quantum_key_length, length_of_check,
    #                                       message_binary,))
    # thread_2 = host_middleware.run_protocol(quantum_receiver_protocol,
    #                                         (host_quantum.host_id, quantum_key_length, length_of_check,))
    #
    # thread_1.join()
    # thread_2.join()

    thread_1 = host_classical.run_protocol(classical_sender_protocol, (host_middleware.host_id, message,))
    thread_2 = host_middleware.run_protocol(classical_receiver_protocol, (host_classical.host_id,))

    thread_1.join()
    thread_2.join()

    print(message)

    network.stop()
