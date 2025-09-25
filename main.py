from qunetsim.components import Host, Network
from protocols.bb84_mlkem_fusion_demo import classical_protocol, middleware_protocol, quantum_protocol

NETWORK_TIMEOUT = 20


def setup_network():
    """
    Initializes and connects the hosts in the network.
    """
    network = Network.get_instance()
    network.start()

    host_classical = Host('Classical Node')
    host_middleware = Host('Middleware Node')
    host_quantum = Host('Quantum Node')

    hosts = [host_classical, host_middleware, host_quantum]

    host_classical.add_c_connection(host_middleware.host_id)
    host_middleware.add_c_connection(host_classical.host_id)
    host_middleware.add_connection(host_quantum.host_id)
    host_quantum.add_connection(host_middleware.host_id)

    network.add_hosts(hosts)

    for host in hosts:
        host.start()

    return network, hosts


def main():
    network, hosts = setup_network()

    classical_node, middleware_node, quantum_node = hosts

    thread_c = classical_node.run_protocol(classical_protocol, (middleware_node.host_id,))
    thread_m = middleware_node.run_protocol(middleware_protocol, (classical_node.host_id, quantum_node.host_id))
    thread_q = quantum_node.run_protocol(quantum_protocol, (middleware_node.host_id,))

    for thread in [thread_c, thread_m, thread_q]:
        thread.join()

    network.stop()


if __name__ == '__main__':
    main()
