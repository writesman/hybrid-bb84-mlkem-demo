import random
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger

Logger.DISABLED = True
KEY_LENGTH = 50
NETWORK_TIMEOUT = 10

def alice_bb84(alice: Host, bob_id: str):
    alice_bits = [random.randint(0, 1) for _ in range(KEY_LENGTH)]
    print(f"\nAlice's random bits: {alice_bits}")

    alice_bases = [random.choice(['Z', 'H']) for _ in range(KEY_LENGTH)]
    print(f"Alice's random bases: {alice_bases}")

    for i in range(KEY_LENGTH):
        q = Qubit(alice)
        if alice_bits[i] == 1:
            q.X()
        if alice_bases[i] == 'H':
            q.H()
        alice.send_qubit(bob_id, q)
    print("\nAlice sent all qubits.")

    alice.send_classical(bob_id, alice_bases)
    print("Alice sent her bases.")

    bob_bases_obj = alice.get_next_classical(bob_id, wait=-1)
    if not bob_bases_obj:
        return None
    bob_bases = bob_bases_obj.content
    print(f"\nAlice received Bob's bases: {bob_bases}")

    sifted_key_alice = []
    for i in range(KEY_LENGTH):
        if alice_bases[i] == bob_bases[i]:
            sifted_key_alice.append(alice_bits[i])
    print(f"Alice's sifted key: {sifted_key_alice}")


def bob_bb84(bob: Host, alice_id: str):
    bob_bases = [random.choice(['Z', 'H']) for _ in range(KEY_LENGTH)]
    print(f"\nBob's random bases: {bob_bases}")

    bob_measured_bits = []
    for i in range(KEY_LENGTH):
        q = bob.get_qubit(alice_id, wait=-1)
        if q:
            if bob_bases[i] == 'H':
                q.H()
            bob_measured_bits.append(q.measure())
    print("\nBob received and measured all qubits.")
    print(f"Bob's measured bits: {bob_measured_bits}")

    alice_bases_obj = bob.get_next_classical(alice_id, wait=-1)
    if not alice_bases_obj:
        return None
    alice_bases = alice_bases_obj.content
    print(f"Bob received Alice's bases: {alice_bases}")

    bob.send_classical(alice_id, bob_bases)
    print("Bob sent his bases.")

    sifted_key_bob = []
    for i in range(KEY_LENGTH):
        if alice_bases[i] == bob_bases[i]:
            sifted_key_bob.append(bob_measured_bits[i])
    print(f"Bob's sifted key: {sifted_key_bob}")


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