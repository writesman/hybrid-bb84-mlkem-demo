import random
import hashlib
import base64
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger
from math import ceil

Logger.DISABLED = True  # Disabling the default logger for a cleaner output.


class BB84:
    """
    Encapsulates the BB84 protocol logic, including an optional eavesdropper and QBER simulation.
    """
    KEY_LENGTH = 256
    KEY_CHECK_RATIO = 0.5
    MAX_ERROR_RATE = 15  # Max tolerable error rate in percent
    NETWORK_TIMEOUT = 20 # wait time in seconds

    @staticmethod
    def _privacy_amplification(sifted_bits: list) -> bytes | None:
        """
        Reduces any partial information an eavesdropper might have by hashing the key.
        """
        if not sifted_bits:
            return None
        bit_string = "".join(map(str, sifted_bits))
        hasher = hashlib.sha256()
        hasher.update(bit_string.encode('utf-8'))
        key_digest = hasher.digest()
        return base64.urlsafe_b64encode(key_digest)

    @staticmethod
    def compute_initial_block_size(error_rate_percent: float) -> int:
        """
        Calculate initial block size based on error rate (percentage).
        """
        qber = error_rate_percent / 100
        if qber <= 0:
            return 16  # fallback default
        return max(4, ceil(0.73 / qber))

    @staticmethod
    def _alice_cascade_protocol(alice: Host, bob_id: str, corrected_key_candidate: list[int], error_rate: float,
                                seed: int = 42, max_passes: int = 10) -> list[int]:
        """

        :param alice:
        :param bob_id:
        :param corrected_key_candidate:
        :param error_rate:
        :param seed:
        :param max_passes:
        :return:
        """
        key = corrected_key_candidate[:]  # Copy to avoid mutating input
        n = len(key)
        initial_block_size = BB84.compute_initial_block_size(error_rate)

        for pass_num in range(max_passes):
            block_size = initial_block_size * (2 ** pass_num)
            indices = list(range(n))
            random.seed(seed + pass_num)
            random.shuffle(indices)

            blocks = [indices[i:i + block_size] for i in range(0, n, block_size)]

            for block_num, block in enumerate(blocks, start=1):
                alice_parity = sum(key[i] for i in block) % 2
                alice.send_classical(bob_id, (block, alice_parity), await_ack=True)
                mismatch = alice.get_next_classical(bob_id, wait=-1).content

                if mismatch:
                    BB84._alice_cascade_binary_search(alice, bob_id, key, block)

            # After each pass, send hash of key to Bob and receive confirmation
            key_hash = hashlib.sha256("".join(map(str, key)).encode('utf-8')).digest()
            alice.send_classical(bob_id, ("KEY_HASH", key_hash), await_ack=True)
            response = alice.get_next_classical(bob_id, wait=-1).content

            if response == "MATCH":
                break
        if response != "MATCH":
            print("Alice: Cascade failed. Keys do not match after all passes.")
            return None
        return key

    @staticmethod
    def _alice_cascade_binary_search(alice: Host, bob_id: str, key: list[int], block: list[int]):
        """Iterative binary search to find the error in a block."""
        while len(block) > 1:
            mid = len(block) // 2
            left = block[:mid]

            # Send parity of the left half to Bob
            left_parity = sum(key[i] for i in left) % 2
            alice.send_classical(bob_id, left_parity, await_ack=True)

            # Bob will tell us if the mismatch is in the left half
            mismatch_in_left = alice.get_next_classical(bob_id, wait=-1).content

            if mismatch_in_left:
                block = left  # Narrow search to the left half
            else:
                block = block[mid:]  # Narrow search to the right half

    @staticmethod
    def _bob_cascade_protocol(bob: Host, alice_id: str, corrected_key_candidate: list[int], error_rate: float,
                              seed: int = 42, max_passes: int = 10) -> list[int]:
        key = corrected_key_candidate[:]  # Copy to avoid mutating input
        n = len(key)
        initial_block_size = BB84.compute_initial_block_size(error_rate)

        for pass_num in range(max_passes):
            block_size = initial_block_size * (2 ** pass_num)
            indices = list(range(n))
            random.seed(seed + pass_num)
            random.shuffle(indices)

            num_blocks = ceil(n / block_size)
            for block_num in range(num_blocks):
                block, alice_parity = bob.get_next_classical(alice_id, wait=-1).content

                bob_parity = sum(key[i] for i in block) % 2
                mismatch = (bob_parity != alice_parity)
                bob.send_classical(alice_id, mismatch, await_ack=True)

                if mismatch:
                    BB84._bob_cascade_binary_search(bob, alice_id, key, block)

            # After each pass, receive Alice's key hash, compare and respond
            msg_type, key_hash = bob.get_next_classical(alice_id, wait=-1).content
            if msg_type == "KEY_HASH":
                bob_key_hash = hashlib.sha256("".join(map(str, key)).encode('utf-8')).digest()
                if bob_key_hash == key_hash:
                    bob.send_classical(alice_id, "MATCH", await_ack=True)
                    break
                else:
                    bob.send_classical(alice_id, "MISMATCH", await_ack=True)

        return key

    @staticmethod
    def _bob_cascade_binary_search(bob: Host, alice_id: str, key: list[int], block: list[int]):
        """
        Iterative binary search to find and correct the error in a block.
        """
        while len(block) > 1:
            mid = len(block) // 2
            left = block[:mid]

            # Receive the parity of the left half from Alice
            alice_left_parity = bob.get_next_classical(alice_id, wait=-1).content

            # Calculate our own parity for the left half
            bob_left_parity = sum(key[i] for i in left) % 2

            mismatch_in_left = (alice_left_parity != bob_left_parity)
            bob.send_classical(alice_id, mismatch_in_left, await_ack=True)

            if mismatch_in_left:
                block = left  # The error is in the left half
            else:
                block = block[mid:]  # The error must be in the right half

        # The block now contains the single index with the error. Flip the bit.
        error_index = block[0]
        key[error_index] ^= 1

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
        alice.send_classical(receiver_id, ("BASES", alice_bases))

        msg_type, bob_bases = alice.get_next_classical(receiver_id, wait=-1).content
        if msg_type != "BASES":
            return None

        sifted_key_indices = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key = [alice_bits[i] for i in sifted_key_indices]
        if not sifted_key:
            print("Alice: No matching bases, protocol failed.")
            return None

        # Step 4: Perform error checking.
        num_samples = ceil(len(sifted_key) * BB84.KEY_CHECK_RATIO)
        if num_samples == 0:
            print("Alice: Sifted key is too short for error checking. Aborting.")
            return None

        sample_indices = sorted(random.sample(range(len(sifted_key)), num_samples))
        sample_values = [sifted_key[i] for i in sample_indices]

        alice.send_classical(receiver_id, ("SAMPLE INFO", sample_indices, sample_values), await_ack=True)
        msg_type, error_rate = alice.get_next_classical(receiver_id, wait=-1).content
        if msg_type != "ERROR RATE":
            return None
        if error_rate > BB84.MAX_ERROR_RATE:
            print(f"Alice: Error rate measured ({error_rate:.2f}%) is too high! Aborting protocol.")
            return None

        # Step 5: Remove sample bits and perform Cascade error reconciliation.
        noisy_key = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]

        reconciled_key = BB84._alice_cascade_protocol(alice, receiver_id, noisy_key, error_rate)

        # Step 6: Perform privacy amplification
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def _apply_depolarizing_noise(qubit: Qubit, qber: float):
        if random.random() < qber:
            error_gate = random.choice([qubit.X, qubit.Y, qubit.Z])
            error_gate()

    @staticmethod
    def bob_protocol(bob: Host, sender_id: str, qber: float = 0.0):
        """
        Bob's part of the BB84 protocol.

        Args:
            bob (Host): The host object for Bob.
            sender_id (str): The ID of the sender (Alice or Eve).
            qber (float): The Quantum Bit Error Rate to simulate (0.0 to 1.0).
        """
        # Step 1: Generate random bases for measurement.
        bob_bases = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        # Step 2: Measure incoming qubits.
        bob_measured_bits = []
        for i in range(BB84.KEY_LENGTH):
            qubit = bob.get_qubit(sender_id, wait=-1)
            BB84._apply_depolarizing_noise(qubit, qber)
            if bob_bases[i] == 'X':
                qubit.H()
            bob_measured_bits.append(qubit.measure())

        # Step 3: Compare bases and create a sifted key.
        msg_type, alice_bases = bob.get_next_classical(sender_id, wait=-1).content
        if msg_type != "BASES":
            return None

        bob.send_classical(sender_id, ("BASES", bob_bases), await_ack=True)

        sifted_key = [bob_measured_bits[i] for i in range(len(bob_measured_bits)) if alice_bases[i] == bob_bases[i]]
        if not sifted_key:
            print("Bob: No matching bases, protocol failed.")
            return None

        # Step 4: Calculate the error rate.
        msg_type, sample_indices, sample_values = bob.get_next_classical(sender_id, wait=-1).content
        if msg_type != "SAMPLE INFO":
            return None

        mismatches = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])

        error_rate = (mismatches / len(sample_indices)) * 100 if sample_indices else 0.0
        bob.send_classical(sender_id, ("ERROR RATE", error_rate), await_ack=True)

        if error_rate > BB84.MAX_ERROR_RATE:
            print(f"Bob: Error rate measured ({error_rate:.2f}%) is too high! Aborting protocol.")
            return None

        # Step 5: Remove sample bits and perform Cascade error reconciliation.
        noisy_key = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]

        reconciled_key = BB84._bob_cascade_protocol(bob, sender_id, noisy_key, error_rate)

        # Step 6: Perform privacy amplification
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def eve_protocol(eve: Host, sender_id: str, receiver_id: str):
        """
        Eve's eavesdropping protocol (intercept-and-resend attack).
        This will naturally introduce errors that Alice and Bob can detect.
        """
        # Forwarding qubits
        for _ in range(BB84.KEY_LENGTH):
            q = eve.get_qubit(sender_id, wait=-1)
            if q:
                eve_basis = random.choice(['Z', 'X'])
                if eve_basis == 'X':
                    q.H()
                measured_bit = q.measure()
                new_q = Qubit(eve)
                if measured_bit == 1:
                    new_q.X()
                if eve_basis == 'X':
                    new_q.H()
                eve.send_qubit(receiver_id, new_q, await_ack=False)

        # Forwarding classical messages
        # Eve must wait for each message and forward it to maintain the protocol flow.
        msg_type, alice_bases = eve.get_next_classical(sender_id, wait=-1).content
        if msg_type != "BASES":
            return None
        eve.send_classical(receiver_id, (msg_type, alice_bases), await_ack=True)

        msg_type, bob_bases = eve.get_next_classical(receiver_id, wait=-1).content
        if msg_type != "BASES":
            return None
        eve.send_classical(sender_id, (msg_type, bob_bases), await_ack=True)

        msg_type, sample_indices, sample_values = eve.get_next_classical(sender_id, wait=-1).content
        if msg_type != "SAMPLE INFO":
            return None
        eve.send_classical(receiver_id, (msg_type, sample_indices, sample_values), await_ack=True)

        msg_type, error_rate = eve.get_next_classical(receiver_id, wait=-1).content
        if msg_type != "ERROR RATE":
            return None
        eve.send_classical(sender_id, (msg_type, error_rate), await_ack=True)

        print("Eve: Intercept-and-resend attack completed.")


def run_bb84(qber=0.0, eavesdropper_present=False):
    """
    Main function to run the BB84 simulation.
    The user can choose whether to include an eavesdropper.
    """
    print("-" * 50)
    if eavesdropper_present:
        print(f"--- Running BB84 Protocol WITH Eavesdropper ---")
    else:
        print(f"--- Running BB84 Protocol with QBER = {qber * 100:.1f}% ---")
    print("-" * 50)

    network = Network.get_instance()
    network.start()

    host_alice = Host('Alice')
    host_bob = Host('Bob')

    if eavesdropper_present:
        host_eve = Host('Eve')
        host_alice.add_connection('Eve')
        host_eve.add_connection('Alice')
        host_eve.add_connection('Bob')
        host_bob.add_connection('Eve')
        network.add_hosts([host_alice, host_bob, host_eve])
    else:
        host_alice.add_connection('Bob')
        host_bob.add_connection('Alice')
        network.add_hosts([host_alice, host_bob])

    host_alice.start()
    host_bob.start()
    if eavesdropper_present:
        host_eve.start()

    if eavesdropper_present:
        # Eve's presence introduces errors, so we set QBER to 0 for Bob
        # to only measure errors caused by Eve.
        t_alice = host_alice.run_protocol(BB84.alice_protocol, (host_eve.host_id,))
        t_eve = host_eve.run_protocol(BB84.eve_protocol, (host_alice.host_id, host_bob.host_id))
        t_bob = host_bob.run_protocol(BB84.bob_protocol, (host_eve.host_id, 0.0))
        t_alice.join()
        t_eve.join()
        t_bob.join()
    else:
        # Pass the configured QBER to Bob's protocol
        t_alice = host_alice.run_protocol(BB84.alice_protocol, (host_bob.host_id,))
        t_bob = host_bob.run_protocol(BB84.bob_protocol, (host_alice.host_id, qber))
        t_alice.join()
        t_bob.join()

    network.stop(True)


if __name__ == '__main__':
    # Scenario 1: No noise, no eavesdropper (should succeed)
    run_bb84(qber=0.00, eavesdropper_present=False)

    # Scenario 2: 5% channel noise (should succeed)
    run_bb84(qber=0.05, eavesdropper_present=False)

    # Scenario 3: 12% channel noise (might succeed or fail, close to the limit)
    run_bb84(qber=0.12, eavesdropper_present=False)

    # Scenario 4: 20% channel noise (should fail)
    run_bb84(qber=0.20, eavesdropper_present=False)

    # Scenario 5: With an eavesdropper (should detect high error rate and fail)
    run_bb84(qber=0.0, eavesdropper_present=True)
