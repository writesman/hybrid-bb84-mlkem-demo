from middleware_sim import setup_network, derive_fernet_key, e91_exchange_bases, e91_perform_chsh_test, e91_extract_key
from quantcrypt.kem import MLKEM_1024
from qunetsim.components import Host, Network
from cryptography.fernet import Fernet
from qunetsim.objects import Logger, Qubit
import random
import numpy as np
from math import ceil

Logger.DISABLED = True
NETWORK_TIMEOUT = 20
MESSAGE_ENCODING = 'utf-8'
QKD_CHECK_RATIO = 0.5
QKD_QUBIT_RATIO = 1


def classical_protocol(host: Host, sender_id: str, kem_instance):
    public_key, secret_key = kem_instance.keygen()

    host.send_classical(sender_id, public_key, await_ack=True)

    ciphertext_obj = host.get_next_classical(sender_id, wait=-1)
    if not ciphertext_obj:
        return None
    ciphertext = ciphertext_obj.content

    shared_secret = kem_instance.decaps(secret_key, ciphertext)

    print(f"classical: {shared_secret}")


def middleware_c_protocol(host: Host, receiver_id: str, kem_instance):
    public_key_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if not public_key_obj:
        return
    public_key = public_key_obj.content

    ciphertext, shared_secret = kem_instance.encaps(public_key)

    host.send_classical(receiver_id, ciphertext, await_ack=True)

    print(f"middleware: {shared_secret}")


def quantum_protocol(host: Host, sender_id: str, dummy):
    msg = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not msg or msg.content == "ABORT":
        return None
    num_pairs = int(msg.content)

    # Step 1: Measure incoming EPR pairs
    bases_b_full = [random.choice([np.pi / 4, np.pi / 2]) for _ in range(num_pairs)]
    bases_b, meas_b = [], []

    for i in range(num_pairs):
        q = host.get_epr(sender_id, wait=NETWORK_TIMEOUT)
        if q:
            basis = bases_b_full[i]
            bases_b.append(basis)
            q.ry(basis)
            meas_b.append(q.measure())

    # Step 2: Exchange bases with Alice
    bases_a, _ = e91_exchange_bases(host, sender_id, bases_b, is_initiator=False)
    if bases_a is None:
        return None

    # Truncate lists to the minimum common length
    min_len = min(len(bases_a), len(bases_b), len(meas_b))
    bases_a, bases_b, meas_b = bases_a[:min_len], bases_b[:min_len], meas_b[:min_len]
    num_pairs = min_len

    if num_pairs == 0:
        return None

    # Step 3: Receive test indices and public measurements from Alice
    test_indices_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not test_indices_obj:
        return None
    test_indices = test_indices_obj.content

    public_meas_a_obj = host.get_next_classical(sender_id, wait=NETWORK_TIMEOUT)
    if not public_meas_a_obj:
        return None
    public_meas_a = public_meas_a_obj.content

    # Step 4: Send measurement outcomes FOR THE TEST SUBSET ONLY
    public_meas_b = {i: meas_b[i] for i in test_indices}
    host.send_classical(sender_id, public_meas_b, await_ack=True)

    # Step 5: Perform Bell Test with the public data
    chsh_bases_a = [bases_a[i] for i in test_indices]
    chsh_bases_b = [bases_b[i] for i in test_indices]
    chsh_meas_a = [public_meas_a[i] for i in test_indices]
    chsh_meas_b = [public_meas_b[i] for i in test_indices]
    s_value = e91_perform_chsh_test(chsh_bases_a, chsh_bases_b, chsh_meas_a, chsh_meas_b)
    print(f"[{host.host_id}] Calculated CHSH S-value: {s_value:.4f}")

    if abs(s_value) <= 2.0:
        return None

    # Step 6: Extract secret key from the remaining PRIVATE subset
    key_indices = sorted(list(set(range(num_pairs)) - set(test_indices)))
    key_gen_bases_a = [bases_a[i] for i in key_indices]
    key_gen_bases_b = [bases_b[i] for i in key_indices]
    key_gen_meas_b = [meas_b[i] for i in key_indices]
    one_time_pad_key = e91_extract_key(key_gen_bases_b, key_gen_bases_a, key_gen_meas_b)

    print(f"quantum otp: {one_time_pad_key}")


def middleware_q_protocol(host: Host, receiver_id: str, dummy):
    required_key_len = 50
    num_pairs = ceil(required_key_len * QKD_QUBIT_RATIO)

    host.send_classical(receiver_id, num_pairs, await_ack=True)

    # Step 1: Create, send, and measure all EPR pairs
    bases_a_full = [random.choice([0, np.pi / 4]) for _ in range(num_pairs)]
    bases_a, meas_a = [], []

    for i in range(num_pairs):
        epr_id, ack_received = host.send_epr(receiver_id, await_ack=True)
        if not ack_received:
            continue
        q = host.get_epr(receiver_id, epr_id)
        if q:
            basis = bases_a_full[i]
            bases_a.append(basis)
            q.ry(basis)
            meas_a.append(q.measure())

    # Update num_pairs to actual number of successful measurements
    num_pairs = len(meas_a)

    # Step 2: Exchange bases with Bob
    _, bases_b = e91_exchange_bases(host, receiver_id, bases_a, is_initiator=True)
    if bases_b is None:
        return

    # Truncate lists to the minimum common length in case of transmission failures
    min_len = min(len(bases_a), len(bases_b), len(meas_a))
    bases_a, bases_b, meas_a = bases_a[:min_len], bases_b[:min_len], meas_a[:min_len]
    num_pairs = min_len

    if num_pairs == 0:
        host.send_classical(receiver_id, "ABORT", await_ack=True)
        return

    # Step 3: Announce a random subset of qubits for the Bell Test
    num_test_qubits = ceil(num_pairs * QKD_CHECK_RATIO)
    all_indices = list(range(num_pairs))
    random.shuffle(all_indices)
    test_indices = sorted(all_indices[:num_test_qubits])
    host.send_classical(receiver_id, test_indices, await_ack=True)

    # Step 4: Exchange measurement outcomes FOR THE TEST SUBSET ONLY
    public_meas_a = {i: meas_a[i] for i in test_indices}
    host.send_classical(receiver_id, public_meas_a, await_ack=True)
    public_meas_b_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if not public_meas_b_obj:
        return
    public_meas_b = public_meas_b_obj.content

    # Step 5: Perform Bell Test with the public data
    chsh_bases_a = [bases_a[i] for i in test_indices]
    chsh_bases_b = [bases_b[i] for i in test_indices]
    chsh_meas_a = [public_meas_a[i] for i in test_indices]
    chsh_meas_b = [public_meas_b[i] for i in test_indices]
    s_value = e91_perform_chsh_test(chsh_bases_a, chsh_bases_b, chsh_meas_a, chsh_meas_b)
    print(f"[{host.host_id}] Calculated CHSH S-value: {s_value:.4f}")

    if abs(s_value) <= 2.0:
        host.send_classical(receiver_id, "ABORT", await_ack=True)
        return

    # Step 6: Extract secret key from the remaining PRIVATE subset
    key_indices = sorted(list(set(all_indices) - set(test_indices)))
    key_gen_bases_a = [bases_a[i] for i in key_indices]
    key_gen_bases_b = [bases_b[i] for i in key_indices]
    key_gen_meas_a = [meas_a[i] for i in key_indices]
    one_time_pad_key = e91_extract_key(key_gen_bases_a, key_gen_bases_b, key_gen_meas_a)

    print(f"middleware otp: {one_time_pad_key}")

    if len(one_time_pad_key) < required_key_len:
        host.send_classical(receiver_id, "ABORT", await_ack=True)
        return



def main():
    pqc_kem_instance = MLKEM_1024()
    network, hosts = setup_network()

    classical_node = hosts['classical']
    middleware_node = hosts['middleware']
    quantum_node = hosts['quantum']

    thread1 = classical_node.run_protocol(classical_protocol, (middleware_node.host_id, pqc_kem_instance))
    thread2 = middleware_node.run_protocol(middleware_c_protocol, (classical_node.host_id, pqc_kem_instance))
    thread3 = middleware_node.run_protocol(middleware_q_protocol, (quantum_node.host_id, "syasdsd"))
    thread4 = quantum_node.run_protocol(quantum_protocol, (middleware_node.host_id, "asdas"))

    for thread in [thread1, thread2, thread3, thread4]:
        thread.join()

    network.stop()


if __name__ == '__main__':
    main()
