from quantcrypt.kem import MLKEM_1024
from qunetsim.components import Host, Network
from bb84 import BB84

NETWORK_TIMEOUT = 20


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


def ml_kem_decapsulate(host: Host, sender_id: str, kem_instance):
    public_key, secret_key = kem_instance.keygen()
    host.send_classical(sender_id, public_key, await_ack=True)
    ciphertext_obj = host.get_next_classical(sender_id, wait=-1)
    if not ciphertext_obj:
        return None
    ciphertext = ciphertext_obj.content
    shared_secret = kem_instance.decaps(secret_key, ciphertext)
    return shared_secret


def ml_kem_encapsulate(host: Host, receiver_id: str, kem_instance):
    public_key_obj = host.get_next_classical(receiver_id, wait=NETWORK_TIMEOUT)
    if not public_key_obj:
        return None
    public_key = public_key_obj.content
    ciphertext, shared_secret = kem_instance.encaps(public_key)
    host.send_classical(receiver_id, ciphertext, await_ack=True)
    return shared_secret


def classical_protocol(host: Host, middleware_id: str, kem_instance):
    pqc_key = ml_kem_decapsulate(host, middleware_id, kem_instance)
    print(f"[{host.host_id}] PQC Key: {pqc_key}")


def middleware_protocol(host: Host, classical_id: str, quantum_id: str, kem_instance):
    pqc_key = ml_kem_encapsulate(host, classical_id, kem_instance)
    print(f"[{host.host_id}] PQC Key: {pqc_key}")

    qkd_key = BB84.alice_protocol(host, quantum_id)
    print(f"[{host.host_id}] QKD Key: {qkd_key}")

    # Find the length of the shorter key
    min_len = min(len(pqc_key), len(qkd_key))

    # Truncate both keys to the minimum length
    pqc_key_truncated = pqc_key[:min_len]
    qkd_key_truncated = qkd_key[:min_len]

    # XOR to create hybrid key
    hybrid_key = bytes([b1 ^ b2 for b1, b2 in zip(pqc_key_truncated, qkd_key_truncated)])
    print(f"[{host.host_id}] Hybrid Key: {hybrid_key}")


def quantum_protocol(host: Host, middleware_id: str):
    qkd_key = BB84.bob_protocol(host, middleware_id)
    print(f"[{host.host_id}] QKD Key: {qkd_key}")


def main():
    pqc_kem_instance = MLKEM_1024()
    network, hosts = setup_network()

    classical_node = hosts['classical']
    middleware_node = hosts['middleware']
    quantum_node = hosts['quantum']

    thread_c = classical_node.run_protocol(classical_protocol, (middleware_node.host_id, pqc_kem_instance))
    thread_m = middleware_node.run_protocol(middleware_protocol,
                                            (classical_node.host_id, quantum_node.host_id, pqc_kem_instance))
    thread_q = quantum_node.run_protocol(quantum_protocol, (middleware_node.host_id,))

    for thread in [thread_c, thread_m, thread_q]:
        thread.join()

    network.stop()


if __name__ == '__main__':
    main()
