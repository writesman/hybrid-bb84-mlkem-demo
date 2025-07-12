import random
import hashlib
import base64
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger
from math import ceil

Logger.DISABLED = True


class BB84:
    """
    Encapsulates the BB84 protocol logic, including an optional eavesdropper and Quantum Bit Error Rate (QBER)
    simulation.
    """
    KEY_LENGTH = 256
    KEY_CHECK_RATIO = 0.5  # Amount of the sifted key to compare
    MAX_ERROR_RATE = 0.15  # Max tolerable error rate in percent
    NETWORK_TIMEOUT = 20  # Wait time in seconds

    @staticmethod
    def _privacy_amplification(reconciled_key: list) -> bytes | None:
        """
        Reduces any partial information an eavesdropper might have by hashing the key.

        Args:
            reconciled_key (list[int]): The reconciled key bits.

        Returns:
            bytes | None: A URL-safe, base64-encoded secure key, or None if the input is empty.
        """
        if not reconciled_key:
            return None
        reconciled_key_str = "".join(map(str, reconciled_key))
        hasher = hashlib.sha256()
        hasher.update(reconciled_key_str.encode('utf-8'))
        reconciled_key_digest = hasher.digest()
        return base64.urlsafe_b64encode(reconciled_key_digest)

    @staticmethod
    def _compute_initial_block_size(error_rate: float) -> int:
        """
        Calculates the initial block size for the Cascade protocol based on the estimated error rate.

        Args:
            error_rate (float): The estimated QBER.

        Returns:
            int: The calculated initial block size.
        """
        if error_rate <= 0:
            return 16  # fallback default
        return max(4, ceil(0.73 / error_rate))

    @staticmethod
    def _receive_classical(host: Host, sender_id: str, expected_type: str | tuple[str] = None) -> tuple | None:
        """
        Safely receives and unpacks a classical message.

        Args:
            host (Host): The QuNetSim host calling this function.
            sender_id (str): ID of the expected message sender.
            expected_type (str, optional): Expected message type.

        Returns:
            tuple | None: The unpacked message content if successful, or None on failure.
        """
        message = host.get_next_classical(sender_id, wait=BB84.NETWORK_TIMEOUT)

        # 1. Handle timeout
        if message is None:
            print(f"{host.host_id}: Timeout waiting for message from {sender_id}.")
            return None

        content = message.content

        # 2. Enforce that all valid content must be a non-empty tuple
        if not isinstance(content, tuple) or not content:
            print(f"{host.host_id}: Received malformed message content (not a non-empty tuple).")
            return None

        # 3. Handle message type validation if an expected type is provided
        if expected_type:
            message_type = content[0]
            if message_type != expected_type:
                print(f"{host.host_id}: Unexpected message type '{message_type}'. Expected '{expected_type}'.")
                return None

        # 4. On success, return the validated tuple content
        return content

    @staticmethod
    def _alice_cascade_protocol(alice: Host, bob_id: str, corrected_key_candidate: list[int], error_rate: float,
                                seed: int = 42, max_passes: int = 10) -> list[int] | None:
        """
        Alice's part of the Cascade error reconciliation protocol.

        Args:
            alice (Host): The Host object for Alice.
            bob_id (str): The ID of Bob.
            corrected_key_candidate (list[int]): Alice's version of the sifted key.
            error_rate (float): The estimated QBER.
            seed (int): A seed for the random number generator.
            max_passes (int): The maximum number of passes for the Cascade protocol.

        Returns:
            list[int] | None: The reconciled key, or None if reconciliation fails.
        """
        key = corrected_key_candidate.copy()
        key_length = len(key)
        initial_block_size = BB84._compute_initial_block_size(error_rate)

        for pass_num in range(max_passes):
            block_size = initial_block_size * (2 ** pass_num)
            indices = list(range(key_length))
            random.seed(seed + pass_num)
            random.shuffle(indices)
            blocks = [indices[i:i + block_size] for i in range(0, key_length, block_size)]

            for block in blocks:
                alice_parity = sum(key[i] for i in block) % 2
                alice.send_classical(bob_id, (block, alice_parity), await_ack=True)
                mismatch = alice.get_next_classical(bob_id, wait=-1).content
                if mismatch:
                    BB84._alice_cascade_binary_search(alice, bob_id, key, block)

            key_hash = hashlib.sha256("".join(map(str, key)).encode('utf-8')).digest()
            alice.send_classical(bob_id, ("KEY_HASH", key_hash), await_ack=True)
            response = alice.get_next_classical(bob_id, wait=-1).content

            if response == "MATCH":
                return key

        print("Alice: Cascade failed. Keys do not match after all passes.")
        return None

    @staticmethod
    def _alice_cascade_binary_search(alice: Host, bob_id: str, key: list[int], block: list[int]) -> None:
        """
        Alice's part of the binary search to find an error in a block.

        Args:
            alice (Host): The Host object for Alice.
            bob_id (str): The ID of Bob.
            key (list[int]): Alice's key.
            block (list[int]): The block of indices with a parity mismatch.
        """
        while len(block) > 1:
            mid = len(block) // 2
            left = block[:mid]
            left_parity = sum(key[i] for i in left) % 2
            alice.send_classical(bob_id, left_parity, await_ack=True)
            mismatch_in_left = alice.get_next_classical(bob_id, wait=-1).content
            block = left if mismatch_in_left else block[mid:]

    @staticmethod
    def _bob_cascade_protocol(bob: Host, alice_id: str, corrected_key_candidate: list[int], error_rate: float,
                              seed: int = 42, max_passes: int = 10) -> list[int] | None:
        """
        Bob's part of the Cascade error reconciliation protocol.

        Args:
            bob (Host): The Host object for Bob.
            alice_id (str): The ID of Alice.
            corrected_key_candidate (list[int]): Bob's version of the sifted key.
            error_rate (float): The estimated QBER.
            seed (int): A seed for the random number generator.
            max_passes (int): The maximum number of passes.

        Returns:
            list[int]: The reconciled key.
        """
        key = corrected_key_candidate.copy()
        key_length = len(key)
        initial_block_size = BB84._compute_initial_block_size(error_rate)

        for pass_num in range(max_passes):
            block_size = initial_block_size * (2 ** pass_num)
            indices = list(range(key_length))
            random.seed(seed + pass_num)
            random.shuffle(indices)
            num_blocks = ceil(key_length / block_size)

            for _ in range(num_blocks):
                block, alice_parity = bob.get_next_classical(alice_id, wait=-1).content
                bob_parity = sum(key[i] for i in block) % 2
                mismatch = (bob_parity != alice_parity)
                bob.send_classical(alice_id, mismatch, await_ack=True)
                if mismatch:
                    BB84._bob_cascade_binary_search(bob, alice_id, key, block)

            msg_type, key_hash = bob.get_next_classical(alice_id, wait=-1).content
            if msg_type == "KEY_HASH":
                bob_key_hash = hashlib.sha256("".join(map(str, key)).encode('utf-8')).digest()
                if bob_key_hash == key_hash:
                    bob.send_classical(alice_id, "MATCH", await_ack=True)
                    return key
                else:
                    bob.send_classical(alice_id, "MISMATCH", await_ack=True)

        print("Bob: Cascade failed. Keys do not match after all passes.")
        return None

    @staticmethod
    def _bob_cascade_binary_search(bob: Host, alice_id: str, key: list[int], block: list[int]) -> None:
        """
        Bob's part of the binary search to find and correct an error in a block.

        Args:
            bob (Host): The Host object for Bob.
            alice_id (str): The ID of Alice.
            key (list[int]): Bob's key, which will be corrected in place.
            block (list[int]): The block of indices with a parity mismatch.
        """
        while len(block) > 1:
            mid = len(block) // 2
            left = block[:mid]
            alice_left_parity = bob.get_next_classical(alice_id, wait=-1).content
            bob_left_parity = sum(key[i] for i in left) % 2
            mismatch_in_left = (alice_left_parity != bob_left_parity)
            bob.send_classical(alice_id, mismatch_in_left, await_ack=True)
            block = left if mismatch_in_left else block[mid:]

        error_index = block[0]
        key[error_index] ^= 1  # Flip the bit

    @staticmethod
    def alice_protocol(alice: Host, receiver_id: str):
        """
        The complete BB84 protocol from Alice's perspective.

        Args:
            alice (Host): The Host object for Alice.
            receiver_id (str): The ID of the intended receiver.

        Returns:
            bytes | None: The final, secure key, or None if the protocol fails.
        """
        # Step 1: Generate random bits and bases
        alice_bits = [random.randint(0, 1) for _ in range(BB84.KEY_LENGTH)]
        alice_bases = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        # Step 2: Create and send qubits
        for i in range(BB84.KEY_LENGTH):
            qubit = Qubit(alice)
            if alice_bits[i] == 1:
                qubit.X()
            if alice_bases[i] == 'X':
                qubit.H()
            alice.send_qubit(receiver_id, qubit, await_ack=False)

        # Step 3: Compare bases with Bob to create the sifted key
        alice.send_classical(receiver_id, ("BASES", alice_bases))

        msg_type, bob_bases = alice.get_next_classical(receiver_id, wait=-1).content
        if msg_type != "BASES":
            return None

        sifted_key_indices = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key = [alice_bits[i] for i in sifted_key_indices]

        if not sifted_key:
            print("Alice: No matching bases, protocol failed.")
            return None

        # Step 4: Perform error checking by comparing a sample of the key
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
            print(f"Alice: Error rate measured ({error_rate * 100:.2f}%) is too high! Aborting protocol.")
            return None

        # Step 5: Perform error reconciliation (Cascade)
        noisy_key = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        reconciled_key = BB84._alice_cascade_protocol(alice, receiver_id, noisy_key, error_rate)

        # Step 6: Perform privacy amplification and return the final key
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def bob_protocol(bob: Host, sender_id: str, qber: float = 0.0) -> bytes | None:
        """
        The complete BB84 protocol from Bob's perspective.

        Args:
            bob (Host): The Host object for Bob.
            sender_id (str): The ID of the sender (Alice or Eve).
            qber (float): The QBER to simulate for channel noise.

        Returns:
            bytes | None: The final, secure key, or None if the protocol fails.
        """
        # Step 1: Generate random bases for measurement
        bob_bases = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        # Step 2: Receive and measure qubits
        bob_measured_bits = []
        for i in range(BB84.KEY_LENGTH):
            qubit = bob.get_qubit(sender_id, wait=-1)
            if random.random() < qber:
                error_gate = random.choice([qubit.X, qubit.Y, qubit.Z])
                error_gate()
            if bob_bases[i] == 'X':
                qubit.H()
            bob_measured_bits.append(qubit.measure())

        # Step 3: Compare bases with Alice to create the sifted key
        msg_type, alice_bases = bob.get_next_classical(sender_id, wait=-1).content
        if msg_type != "BASES":
            return None

        bob.send_classical(sender_id, ("BASES", bob_bases), await_ack=True)

        sifted_key_indices = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key = [bob_measured_bits[i] for i in sifted_key_indices]

        if not sifted_key:
            print("Bob: No matching bases, protocol failed.")
            return None

        # Step 4: Calculate the error rate
        msg_type, sample_indices, sample_values = bob.get_next_classical(sender_id, wait=-1).content
        if msg_type != "SAMPLE INFO":
            return None

        mismatches = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])
        error_rate = (mismatches / len(sample_indices)) if sample_indices else 0.0
        bob.send_classical(sender_id, ("ERROR RATE", error_rate), await_ack=True)

        if error_rate > BB84.MAX_ERROR_RATE:
            print(f"Bob: Error rate measured ({error_rate * 100:.2f}%) is too high! Aborting protocol.")
            return None

        # Step 5: Perform error reconciliation (Cascade)
        noisy_key = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        reconciled_key = BB84._bob_cascade_protocol(bob, sender_id, noisy_key, error_rate)

        # Step 6: Perform privacy amplification and return the final key
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def eve_protocol(eve: Host, sender_id: str, receiver_id: str):
        """
        Eve's eavesdropping protocol using an intercept-and-resend attack.

        Args:
            eve (Host): The Host object for Eve.
            sender_id (str): The ID of the original sender (Alice).
            receiver_id (str): The ID of the intended receiver (Bob).
        """
        # Forwarding qubits
        for _ in range(BB84.KEY_LENGTH):
            qubit = eve.get_qubit(sender_id, wait=-1)
            eve_basis = random.choice(['Z', 'X'])
            if eve_basis == 'X':
                qubit.H()
            measured_bit = qubit.measure()

            new_qubit = Qubit(eve)
            if measured_bit == 1:
                new_qubit.X()
            if eve_basis == 'X':
                new_qubit.H()
            eve.send_qubit(receiver_id, new_qubit, await_ack=False)

        # Forward classical messages back and forth
        # 1. Alice -> Eve -> Bob (Bases)
        alice_bases_msg = eve.get_next_classical(sender_id, wait=-1).content
        eve.send_classical(receiver_id, alice_bases_msg, await_ack=True)
        # 2. Bob -> Eve -> Alice (Bases)
        bob_bases_msg = eve.get_next_classical(receiver_id, wait=-1).content
        eve.send_classical(sender_id, bob_bases_msg, await_ack=True)
        # 3. Alice -> Eve -> Bob (Sample Info)
        sample_info_msg = eve.get_next_classical(sender_id, wait=-1).content
        eve.send_classical(receiver_id, sample_info_msg, await_ack=True)
        # 4. Bob -> Eve -> Alice (Error Rate)
        error_rate_msg = eve.get_next_classical(receiver_id, wait=-1).content
        eve.send_classical(sender_id, error_rate_msg, await_ack=True)

        print("Eve: Intercept-and-resend attack completed.")


def run_bb84(qber=0.0, eavesdropper_present=False) -> None:
    """
    Sets up and runs a simulation of the BB84 protocol.

    Args:
        qber (float): The Quantum Bit Error Rate to simulate (0.0 to 1.0).
        eavesdropper_present (bool): If True, an eavesdropper (Eve) is added.
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
        # Route communication through Eve
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
        # Alice sends to Eve, Eve to Bob
        # Eve's presence introduces errors, so we set QBER to 0 for Bob
        t_alice = host_alice.run_protocol(BB84.alice_protocol, (host_eve.host_id,))
        t_eve = host_eve.run_protocol(BB84.eve_protocol, (host_alice.host_id, host_bob.host_id))
        t_bob = host_bob.run_protocol(BB84.bob_protocol, (host_eve.host_id, 0.0))
        t_alice.join()
        t_eve.join()
        t_bob.join()
    else:
        # Alice sends directly to Bob
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
