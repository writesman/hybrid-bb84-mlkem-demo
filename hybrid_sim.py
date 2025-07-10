from quantcrypt.kem import MLKEM_1024
from qunetsim.components import Host, Network

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
    shared_secret = ml_kem_decapsulate(host, middleware_id, kem_instance)
    print(f"[{host.host_id}] Shared secret: {shared_secret}")


def middleware_protocol(host: Host, classical_id: str, kem_instance):
    shared_secret = ml_kem_encapsulate(host, classical_id, kem_instance)
    print(f"[{host.host_id}] Shared secret: {shared_secret}")


def main():
    pqc_kem_instance = MLKEM_1024()
    network, hosts = setup_network()

    classical_node = hosts['classical']
    middleware_node = hosts['middleware']
    quantum_node = hosts['quantum']

    thread1 = classical_node.run_protocol(classical_protocol, (middleware_node.host_id, pqc_kem_instance))
    thread2 = middleware_node.run_protocol(middleware_protocol, (classical_node.host_id, pqc_kem_instance))

    for thread in [thread1, thread2]:
        thread.join()

    network.stop()


if __name__ == '__main__':
    main()
