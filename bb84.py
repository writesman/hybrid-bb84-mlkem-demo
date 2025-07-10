import random
import hashlib
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger
from math import ceil

Logger.DISABLED = True  # Disabling the default logger for a cleaner output.


class BB84:
    """
    Encapsulates the BB84 protocol logic, including an optional eavesdropper.
    """
    KEY_LENGTH = 20
    KEY_CHECK_RATIO = 0.5
    MAX_ERROR_RATE = 15.0  # Max tolerable error rate in percent

    @staticmethod
    def _privacy_amplification(key: list) -> str:
        """
        Reduces any partial information an eavesdropper might have by hashing the key.
        """
        key_string = "".join(map(str, key))
        # Use SHA-256 to create a new, shorter, and more secure key.
        hasher = hashlib.sha256()
        hasher.update(key_string.encode('utf-8'))
        return hasher.hexdigest()

    @staticmethod
    def alice_protocol(alice: Host, receiver_id: str):
        """
        Alice's part of the BB84 protocol.
        """
        # Step 1: Generate random bits and bases.
        alice_bits = [random.randint(0, 1) for _ in range(BB84.KEY_LENGTH)]
        alice_bases = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        # Step 2: Encode and send qubits.
        for i in range(BB84.KEY_LENGTH):
            q = Qubit(alice)
            if alice_bits[i] == 1:
                q.X()
            if alice_bases[i] == 'X':
                q.H()
            alice.send_qubit(receiver_id, q, await_ack=False)

        # Step 3: Compare bases and create a sifted key.
        alice.send_classical(receiver_id, alice_bases)
        bob_bases = alice.get_next_classical(receiver_id, wait=-1).content

        sifted_key = [alice_bits[i] for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        if not sifted_key:
            print("Alice: No matching bases, protocol failed.")
            return None

        # Step 4: Perform error checking.
        num_samples = ceil(len(sifted_key) * BB84.KEY_CHECK_RATIO)
        sample_indices = sorted(random.sample(range(len(sifted_key)), num_samples))
        sample_values = [sifted_key[i] for i in sample_indices]

        alice.send_classical(receiver_id, (sample_indices, sample_values))
        error_rate = alice.get_next_classical(receiver_id, wait=-1).content

        if error_rate > BB84.MAX_ERROR_RATE:
            print(f"Alice: Error rate is too high! Aborting protocol.")
            return None

        # Step 5: Generate the final secure key.
        final_key_bits = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        final_key = BB84._privacy_amplification(final_key_bits)
        print(f"Alice: Final key: {final_key}")
        return final_key

    @staticmethod
    def bob_protocol(bob: Host, sender_id: str):
        """
        Bob's part of the BB84 protocol.
        """
        # Step 1: Generate random bases for measurement.
        bob_bases = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        # Step 2: Measure incoming qubits.
        bob_measured_bits = []
        for i in range(BB84.KEY_LENGTH):
            q = bob.get_qubit(sender_id, wait=-1)
            if q:
                if bob_bases[i] == 'X':
                    q.H()
                bob_measured_bits.append(q.measure())

        # Step 3: Compare bases and create a sifted key.
        alice_bases = bob.get_next_classical(sender_id, wait=-1).content
        bob.send_classical(sender_id, bob_bases)

        sifted_key = [bob_measured_bits[i] for i in range(len(bob_measured_bits)) if alice_bases[i] == bob_bases[i]]
        if not sifted_key:
            print("Bob: No matching bases, protocol failed.")
            return None

        # Step 4: Calculate the error rate.
        sample_indices, sample_values = bob.get_next_classical(sender_id, wait=-1).content

        mismatches = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])

        error_rate = (mismatches / len(sample_indices)) * 100 if sample_indices else 0.0
        bob.send_classical(sender_id, error_rate)

        if error_rate > BB84.MAX_ERROR_RATE:
            print("Bob: Error rate is too high! Aborting protocol.")
            return None

        # Step 5: Generate the final secure key.
        final_key_bits = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        final_key = BB84._privacy_amplification(final_key_bits)
        print(f"Bob: Final key: {final_key}")
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

    t_alice = host_alice.run_protocol(BB84.alice_protocol, (host_bob.host_id,))
    t_bob = host_bob.run_protocol(BB84.bob_protocol, (host_alice.host_id,))

    t_alice.join()
    t_bob.join()
    network.stop(True)
