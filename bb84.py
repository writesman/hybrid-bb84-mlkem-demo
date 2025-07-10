import random
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger
from math import ceil

Logger.DISABLED = True
BB84_KEY_LENGTH = 50
BB84_KEY_CHECK_RATIO = 0.5
NETWORK_TIMEOUT = 10
BB84_MAX_ERROR_RATE = 15


def alice_bb84(alice: Host, bob_id: str):
    # Step 1: Generate random bits/bases
    alice_bits = [random.randint(0, 1) for _ in range(BB84_KEY_LENGTH)]
    alice_bases = [random.choice(['Z', 'H']) for _ in range(BB84_KEY_LENGTH)]

    # Step 2: Prepare and send qubits
    for i in range(BB84_KEY_LENGTH):
        q = Qubit(alice)
        if alice_bits[i] == 1: q.X()
        if alice_bases[i] == 'H': q.H()
        alice.send_qubit(bob_id, q)

    # Step 3: Compare bases
    alice.send_classical(bob_id, alice_bases)
    bob_bases = alice.get_next_classical(bob_id, wait=-1).content

    # Step 4: Calculate sifted key
    sifted_key = [alice_bits[i] for i in range(BB84_KEY_LENGTH) if alice_bases[i] == bob_bases[i]]

    # Step 5: Error checking
    num_samples = ceil(len(sifted_key) * BB84_KEY_CHECK_RATIO)
    sample_indices = sorted(random.sample(range(len(sifted_key)), num_samples))
    sample_values = [sifted_key[i] for i in sample_indices]

    alice.send_classical(bob_id, sample_indices)
    alice.send_classical(bob_id, sample_values)

    error_rate = alice.get_next_classical(bob_id, wait=-1).content
    if error_rate > BB84_MAX_ERROR_RATE:
        return -1

    # Step 6: Generate final key
    final_key = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
    return final_key

def bob_bb84(bob: Host, alice_id: str):
    # Step 1: Generate random bases
    bob_bases = [random.choice(['Z', 'H']) for _ in range(BB84_KEY_LENGTH)]

    # Step 2: Measure incoming qubits
    bob_measured_bits = []
    for i in range(BB84_KEY_LENGTH):
        q = bob.get_qubit(alice_id, wait=-1)
        if q:
            if bob_bases[i] == 'H':
                q.H()
            bob_measured_bits.append(q.measure())

    # Step 3: Compare bases
    alice_bases = bob.get_next_classical(alice_id, wait=-1).content
    bob.send_classical(alice_id, bob_bases)

    # Step 4: Calculate sifted key
    sifted_key = [bob_measured_bits[i] for i in range(BB84_KEY_LENGTH) if alice_bases[i] == bob_bases[i]]

    # Step 5: Error checking
    sample_indices = bob.get_next_classical(alice_id, wait=-1).content
    sample_values = bob.get_next_classical(alice_id, wait=-1).content

    mismatches = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])
    error_rate = (mismatches / len(sample_indices)) * 100
    bob.send_classical(alice_id, error_rate)

    if error_rate > BB84_MAX_ERROR_RATE:
        return -1

    # Step 6: Generate final key
    final_key = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
    return final_key

def main():
    network = Network.get_instance()
    nodes = ['Alice', 'Bob']
    network.start(nodes)

    host_alice = Host('Alice')
    host_bob = Host('Bob')

    host_alice.add_connection('Bob')
    host_bob.add_connection('Alice')

    host_alice.start()
    host_bob.start()
    network.add_host(host_alice)
    network.add_host(host_bob)

    t_alice = host_alice.run_protocol(alice_bb84, (host_bob.host_id,))
    t_bob = host_bob.run_protocol(bob_bb84, (host_alice.host_id,))

    t_alice.join()
    t_bob.join()
    network.stop(True)


if __name__ == '__main__':
    main()
