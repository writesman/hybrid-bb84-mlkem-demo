from qunetsim.components import Host, Network
from bb84 import BB84


def run_bb84(simulated_qber: float = 0.0, eavesdropper_present: bool = False) -> None:
    """
    Sets up and runs a simulation of the BB84 protocol.

    Args:
        simulated_qber: The Quantum Bit Error Rate to simulate (0.0 to 1.0).
        eavesdropper_present: If True, an eavesdropper (Eve) is added to the network.
    """
    network = Network.get_instance()
    network.start()

    host_alice = Host('Alice')
    host_bob = Host('Bob')
    hosts = [host_alice, host_bob]

    if eavesdropper_present:
        host_eve = Host('Eve')
        hosts.append(host_eve)

        host_alice.add_connection(host_eve.host_id)
        host_eve.add_connection(host_alice.host_id)
        host_eve.add_connection(host_bob.host_id)
        host_bob.add_connection(host_eve.host_id)
    else:
        host_alice.add_connection(host_bob.host_id)
        host_bob.add_connection(host_alice.host_id)

    network.add_hosts(hosts)

    for host in hosts:
        host.start()

    threads = []

    if eavesdropper_present:
        threads.append(host_alice.run_protocol(BB84.alice_protocol, (host_eve.host_id, eavesdropper_present)))
        threads.append(host_eve.run_protocol(BB84.eve_protocol, (host_alice.host_id, host_bob.host_id)))
        threads.append(host_bob.run_protocol(BB84.bob_protocol, (host_eve.host_id, 0.0)))
    else:
        threads.append(host_alice.run_protocol(BB84.alice_protocol, (host_bob.host_id, eavesdropper_present)))
        threads.append(host_bob.run_protocol(BB84.bob_protocol, (host_alice.host_id, simulated_qber)))

    for thread in threads:
        thread.join()

    network.stop(True)


def main() -> None:
    """
    Runs a series of predefined scenarios for the BB84 simulation.
    """
    scenarios = [
        {
            "description": "With an eavesdropper (should fail)",
            "simulated_qber": 0.0,
            "eavesdropper_present": True
        },
        {
            "description": "No noise, no eavesdropper (should succeed)",
            "simulated_qber": 0.00,
            "eavesdropper_present": False
        },
        {
            "description": "5% channel noise (should succeed)",
            "simulated_qber": 0.05,
            "eavesdropper_present": False
        },
        {
            "description": "10% channel noise (may succeed or fail)",
            "simulated_qber": 0.10,
            "eavesdropper_present": False
        },
        {
            "description": "20% channel noise (should fail)",
            "simulated_qber": 0.20,
            "eavesdropper_present": False
        },
    ]

    for i, scenario in enumerate(scenarios):
        print(f"===== Scenario {i + 1}: {scenario['description']} =====")
        run_bb84(simulated_qber=scenario['simulated_qber'], eavesdropper_present=scenario['eavesdropper_present'])


if __name__ == '__main__':
    main()
