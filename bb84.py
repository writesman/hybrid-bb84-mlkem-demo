import random
import hashlib
import base64
from qunetsim.components import Host
from qunetsim.objects import Qubit, Logger
from math import ceil
from typing import Any

Logger.DISABLED = True


class BB84ProtocolError(Exception):
    """
    Custom exception for errors during the BB84 protocol.
    """
    pass


class BB84:
    """
    Encapsulates the BB84 protocol logic, including an optional eavesdropper and QBER simulation.
    """
    KEY_CHECK_RATIO: float = 0.5  # Amount of the sifted key to compare
    KEY_LENGTH: int = 256
    MAX_QBER: float = 0.15  # Max tolerable QBER
    NETWORK_TIMEOUT: int = 20  # Wait time in seconds

    # Protocol Entry Points

    @staticmethod
    def alice_protocol(alice: Host, receiver_id: str, eavesdropper_present: bool = False) -> bytes | None:
        """
        Executes the BB84 protocol from Alice's (the sender's) perspective.

        Args:
            alice: The Host object for Alice.
            receiver_id: The network ID of the intended receiver (Bob).
            eavesdropper_present: If True, waits for qubit receipt acknowledgements.

        Returns:
            The final, secure key as a bytes object, or None if reconciliation fails.

        Raises:
            BB84ProtocolError: If a timeout occurs, a message is malformed, the sifted key is unusable, or the QBER is
            too high.
        """
        try:
            # Step 1: Generate random bits and bases
            alice_bits: list[int] = [random.randint(0, 1) for _ in range(BB84.KEY_LENGTH)]
            alice_bases: list[str] = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

            # Step 2: Create and send qubits
            for i in range(BB84.KEY_LENGTH):
                qubit = Qubit(alice)
                if alice_bits[i] == 1:
                    qubit.X()
                if alice_bases[i] == 'X':
                    qubit.H()
                alice.send_qubit(receiver_id, qubit, await_ack=eavesdropper_present)

            # Step 3: Compare bases with Bob to create the sifted key
            alice.send_classical(receiver_id, ("BASES", alice_bases), await_ack=True)
            bob_bases: list[str] = BB84._receive_classical(alice, receiver_id, "BASES")

            sifted_key_indices: list[int] = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
            sifted_key: list[int] = [alice_bits[i] for i in sifted_key_indices]

            if not sifted_key:
                raise BB84ProtocolError(f"{alice.host_id}: ERROR - No matching bases found. Aborting protocol.")

            # Step 4: Perform error checking
            num_samples: int = ceil(len(sifted_key) * BB84.KEY_CHECK_RATIO)
            if num_samples == 0:
                raise BB84ProtocolError(f"{alice.host_id}: ERROR - Sifted key is too short for error checking. "
                                        f"Aborting protocol.")

            sample_indices: list[int] = sorted(random.sample(range(len(sifted_key)), num_samples))
            sample_values: list[int] = [sifted_key[i] for i in sample_indices]
            alice.send_classical(receiver_id, ("SAMPLE_INFO", sample_indices, sample_values))

            estimated_qber: float = BB84._receive_classical(alice, receiver_id, "ERROR_RATE")

            if estimated_qber > BB84.MAX_QBER:
                raise BB84ProtocolError(f"{alice.host_id}: ERROR - Estimated QBER ({estimated_qber * 100:.2f}%) exceeds"
                                        f" maximum of {BB84.MAX_QBER * 100}%. Aborting protocol.")

            # Step 5: Perform error reconciliation (Cascade)
            noisy_key: list[int] = [bit for i, bit in enumerate(sifted_key) if i not in sample_indices]
            reconciled_key: list[int] | None = BB84._alice_cascade_protocol(alice, receiver_id, noisy_key,
                                                                            estimated_qber)

            # Step 6: Perform privacy amplification and return the final key
            return BB84._privacy_amplification(reconciled_key)

        except BB84ProtocolError as e:
            print(e)

    @staticmethod
    def bob_protocol(bob: Host, sender_id: str, simulated_qber: float = 0.0) -> bytes | None:
        """
        Executes the BB84 protocol from Bob's (the receiver's) perspective.

        Args:
            bob: The Host object for Bob.
            sender_id: The network ID of the sender (Alice).
            simulated_qber: The Quantum Bit Error Rate to simulate for channel noise.

        Returns:
            The final, secure key as a bytes object, or None if reconciliation fails.

        Raises:
            BB84ProtocolError: If a timeout occurs, a message is malformed,
                               the sifted key is unusable, or the QBER is too high.
        """
        try:
            # Step 1: Generate random bases for measurement
            bob_bases: list[str] = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

            # Step 2: Receive and measure qubits
            bob_measured_bits: list[int] = []
            for i in range(BB84.KEY_LENGTH):
                qubit = bob.get_qubit(sender_id, wait=BB84.NETWORK_TIMEOUT)
                if qubit is None:
                    raise BB84ProtocolError(f"{bob.host_id}: ERROR - Timeout waiting for qubit {i + 1} from "
                                            f"{sender_id}. Aborting protocol.")

                if random.random() < simulated_qber:
                    random.choice([qubit.X(), qubit.Y(), qubit.Z()])

                if bob_bases[i] == 'X':
                    qubit.H()
                bob_measured_bits.append(qubit.measure())

            # Step 3: Compare bases with Alice to create the sifted key
            alice_bases: list[str] = BB84._receive_classical(bob, sender_id, "BASES")
            bob.send_classical(sender_id, ("BASES", bob_bases), await_ack=True)

            sifted_key_indices: list[int] = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
            sifted_key: list[int] = [bob_measured_bits[i] for i in sifted_key_indices]
            if not sifted_key:
                raise BB84ProtocolError(f"{bob.host_id}: ERROR - No matching bases found. Aborting protocol.")

            # Step 4: Calculate the error rate
            sample_indices, sample_values = BB84._receive_classical(bob, sender_id, "SAMPLE_INFO")
            mismatches: int = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])
            estimated_qber: float = (mismatches / len(sample_indices)) if sample_indices else 0.0
            bob.send_classical(sender_id, ("ERROR_RATE", estimated_qber))

            if estimated_qber > BB84.MAX_QBER:
                raise BB84ProtocolError(f"{bob.host_id}: ERROR - Estimated QBER ({estimated_qber * 100:.2f}%) exceeds "
                                        f"maximum of {BB84.MAX_QBER * 100}%. Aborting protocol.")

            # Step 5: Perform error reconciliation (Cascade)
            noisy_key: list[int] = [bit for i, bit in enumerate(sifted_key) if i not in sample_indices]
            reconciled_key: list[int] | None = BB84._bob_cascade_protocol(bob, sender_id, noisy_key, estimated_qber)

            # Step 6: Perform privacy amplification and return the final key
            return BB84._privacy_amplification(reconciled_key)

        except BB84ProtocolError as e:
            print(e)

    @staticmethod
    def eve_protocol(eve: Host, sender_id: str, receiver_id: str) -> None:
        """
        Executes an intercept-and-resend eavesdropping attack.

        Args:
            eve: The Host object for Eve.
            sender_id: The network ID of the original sender (Alice).
            receiver_id: The network ID of the intended receiver (Bob).
        """
        try:
            # Intercept and resend qubits
            eve_bases: list[str] = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]
            for i in range(BB84.KEY_LENGTH):
                qubit = eve.get_qubit(sender_id, wait=BB84.NETWORK_TIMEOUT)
                if qubit is None:
                    raise BB84ProtocolError(f"Timeout waiting for qubit {i + 1}")

                # Eve's measurement
                if eve_bases[i] == 'X':
                    qubit.H()
                measured_bit = qubit.measure()

                # Resend a new qubit based on measurement
                new_qubit = Qubit(eve)
                if measured_bit == 1:
                    new_qubit.X()
                if eve_bases[i] == 'X':
                    new_qubit.H()
                eve.send_qubit(receiver_id, new_qubit, await_ack=True)

            # Forward all classical communication
            BB84._forward_classical_message(eve, sender_id, receiver_id)  # Alice -> Bob (bases)
            BB84._forward_classical_message(eve, receiver_id, sender_id)  # Bob -> Alice (bases)
            BB84._forward_classical_message(eve, sender_id, receiver_id)  # Alice -> Bob (sample info)
            BB84._forward_classical_message(eve, receiver_id, sender_id)  # Bob -> Alice (error rate)

        except BB84ProtocolError as e:
            print(e)

    # Cascade Protocol Logic

    @staticmethod
    def _alice_cascade_protocol(alice: Host, bob_id: str, noisy_key: list[int], estimated_qber: float, seed: int = 42,
                                max_passes: int = 10) -> list[int] | None:
        """
        Executes Alice's part of the Cascade error reconciliation protocol.

        Args:
            alice: The Host object for Alice.
            bob_id: The network ID of Bob.
            noisy_key: Alice's version of the sifted key, possibly with errors.
            estimated_qber: The QBER calculated from the key sampling phase.
            seed: A seed for the random number generator to ensure blocks are the same for both parties.
            max_passes: The maximum number of passes for the Cascade protocol.

        Returns:
            The reconciled key as a list of integers, or None if reconciliation fails.
        """
        working_key: list[int] = noisy_key.copy()
        key_length: int = len(working_key)
        initial_block_size: int = BB84._compute_initial_block_size(estimated_qber)

        for pass_num in range(max_passes):
            block_size: int = initial_block_size * (2 ** pass_num)
            indices: list[int] = list(range(key_length))
            random.seed(seed + pass_num)
            random.shuffle(indices)
            blocks: list[list[int]] = [indices[i:i + block_size] for i in range(0, key_length, block_size)]

            for block in blocks:
                alice_parity: int = sum(working_key[i] for i in block) % 2
                alice.send_classical(bob_id, ("CASCADE_BLOCK", block, alice_parity), await_ack=True)
                mismatch: bool = BB84._receive_classical(alice, bob_id, "CASCADE_MISMATCH")
                if mismatch is None:
                    return None
                if mismatch:
                    BB84._alice_cascade_binary_search(alice, bob_id, working_key, block)

            key_hash: bytes = hashlib.sha256("".join(map(str, working_key)).encode('utf-8')).digest()
            alice.send_classical(bob_id, ("KEY_HASH", key_hash), await_ack=True)

            is_match: bool = BB84._receive_classical(alice, bob_id, "KEY_HASH_ACK")
            if is_match is None:
                return None
            if is_match:
                return working_key

        print(f"{alice.host_id}: ERROR - Cascade reconciliation failed after all passes. Aborting protocol.")
        return None

    @staticmethod
    def _bob_cascade_protocol(bob: Host, alice_id: str, noisy_key: list[int], estimated_qber: float, seed: int = 42,
                              max_passes: int = 10) -> list[int] | None:
        """
        Executes Bob's part of the Cascade error reconciliation protocol.

        Args:
            bob: The Host object for Bob.
            alice_id: The network ID of Alice.
            noisy_key: Bob's version of the sifted key, possibly with errors.
            estimated_qber: The calculated QBER.
            seed: A seed for the random number generator.
            max_passes: The maximum number of passes.

        Returns:
            The reconciled key as a list of integers, or None if reconciliation fails.
        """
        working_key: list[int] = noisy_key.copy()
        key_length: int = len(working_key)
        initial_block_size: int = BB84._compute_initial_block_size(estimated_qber)

        for pass_num in range(max_passes):
            block_size: int = initial_block_size * (2 ** pass_num)
            indices: list[int] = list(range(key_length))
            random.seed(seed + pass_num)
            random.shuffle(indices)
            num_blocks: int = ceil(key_length / block_size)

            for _ in range(num_blocks):
                payload: tuple | None = BB84._receive_classical(bob, alice_id, "CASCADE_BLOCK")
                if payload is None:
                    return None
                block, alice_parity = payload

                bob_parity: int = sum(working_key[i] for i in block) % 2
                mismatch: bool = (bob_parity != alice_parity)
                bob.send_classical(alice_id, ("CASCADE_MISMATCH", mismatch), await_ack=True)

                if mismatch:
                    BB84._bob_cascade_binary_search(bob, alice_id, working_key, block)

            key_hash: bytes = BB84._receive_classical(bob, alice_id, "KEY_HASH")
            if key_hash is None:
                return None

            bob_key_hash: bytes = hashlib.sha256("".join(map(str, working_key)).encode('utf-8')).digest()

            is_match: bool = (bob_key_hash == key_hash)
            bob.send_classical(alice_id, ("KEY_HASH_ACK", is_match), await_ack=True)

            if is_match:
                return working_key

        print(f"{bob.host_id}: ERROR - Cascade reconciliation failed after all passes. Aborting protocol.")
        return None

    @staticmethod
    def _alice_cascade_binary_search(alice: Host, bob_id: str, key: list[int], block: list[int]) -> None:
        """
        Executes Alice's part of the binary search to find an error in a block.

        Args:
            alice: The Host object for Alice.
            bob_id: The network ID of Bob.
            key: Alice's working key.
            block: The list of indices in the key that has a parity mismatch.
        """
        while len(block) > 1:
            mid: int = len(block) // 2
            left: list[int] = block[:mid]
            left_parity: int = sum(key[i] for i in left) % 2
            alice.send_classical(bob_id, ("CASCADE_SUB_PARITY", left_parity), await_ack=True)

            mismatch_in_left: bool = BB84._receive_classical(alice, bob_id, "CASCADE_SUB_MISMATCH")
            if mismatch_in_left is None:
                return
            block = left if mismatch_in_left else block[mid:]

    @staticmethod
    def _bob_cascade_binary_search(bob: Host, alice_id: str, key: list[int], block: list[int]) -> None:
        """
        Executes Bob's part of the binary search to find and correct an error in a block.

        Args:
            bob: The Host object for Bob.
            alice_id: The network ID of Alice.
            key: Bob's working key (will be corrected in place).
            block: The list of indices in the key that has a parity mismatch.
        """
        while len(block) > 1:
            mid: int = len(block) // 2
            left: list[int] = block[:mid]

            alice_left_parity: int = BB84._receive_classical(bob, alice_id, "CASCADE_SUB_PARITY")
            if alice_left_parity is None:
                return

            bob_left_parity: int = sum(key[i] for i in left) % 2
            mismatch_in_left: bool = (alice_left_parity != bob_left_parity)
            bob.send_classical(alice_id, ("CASCADE_SUB_MISMATCH", mismatch_in_left), await_ack=True)

            block = left if mismatch_in_left else block[mid:]

        error_index: int = block[0]
        key[error_index] ^= 1

    # Helper Functions

    @staticmethod
    def _receive_classical(host: Host, sender_id: str, expected_type: str) -> Any:
        """
        Safely receives and validates a specific classical message.

        Args:
            host: The QuNetSim host receiving the message.
            sender_id: The network ID of the expected sender.
            expected_type: The expected type string of the message.

        Returns:
            The message payload.

        Raises:
            BB84ProtocolError: If a timeout occurs, the message is malformed, or the message type is unexpected.
        """
        message = host.get_next_classical(sender_id, wait=BB84.NETWORK_TIMEOUT)

        if message is None:
            raise BB84ProtocolError(f"{host.host_id}: ERROR - Timeout waiting for '{expected_type}' message from "
                                    f"{sender_id}. Aborting protocol.")

        content = message.content

        if not isinstance(content, tuple) or not content:
            raise BB84ProtocolError(f"{host.host_id}: ERROR - Received malformed message. Aborting protocol.")

        if expected_type:
            message_type = content[0]
            if message_type != expected_type:
                raise BB84ProtocolError(f"{host.host_id}: ERROR - Received unexpected message type '{message_type}' "
                                        f"from {sender_id}. Expected '{expected_type}'. Aborting protocol.")
            payload = content[1:]
        else:
            payload = content

        return payload[0] if len(payload) == 1 else payload

    @staticmethod
    def _forward_classical_message(host: Host, sender_id: str, receiver_id: str) -> None:
        """
        Intercepts a message from a source and forwards it to a destination.

        Args:
            host: The host performing the forwarding (Eve).
            sender_id: The original sender of the message.
            receiver_id: The intended destination of the message.

        Returns:
            None.

        Raises:
            BB84ProtocolError: If a timeout occurs while waiting for the message.
        """
        message = host.get_next_classical(sender_id, wait=BB84.NETWORK_TIMEOUT)
        if message is None:
            raise BB84ProtocolError(f"{host.host_id}: ERROR - Timeout waiting for message from {sender_id} to forward. "
                                    f"Aborting protocol.")

        host.send_classical(receiver_id, message.content, await_ack=True)

    # Utility Functions

    @staticmethod
    def _privacy_amplification(reconciled_key: list[int] | None) -> bytes | None:
        """
        Reduces partial information an eavesdropper might have by hashing the key.

        This creates a shorter, more secure key from the reconciled key.

        Args:
            reconciled_key: The error-corrected key bits.

        Returns:
            A URL-safe, base64-encoded secure key as a bytes object, or None if the input is empty.

        Raises:
            ValueError: If the reconciled_key contains non-binary values.
        """
        if not reconciled_key:
            return None

        if not all(bit in (0, 1) for bit in reconciled_key):
            raise ValueError("Invalid key format: reconciled_key must contain only 0s and 1s.")

        reconciled_key_str = "".join(map(str, reconciled_key))
        hasher = hashlib.sha256()
        hasher.update(reconciled_key_str.encode('utf-8'))
        reconciled_key_digest = hasher.digest()
        return base64.urlsafe_b64encode(reconciled_key_digest)

    @staticmethod
    def _compute_initial_block_size(estimated_qber: float) -> int:
        """
        Calculates the initial block size for the Cascade protocol based on the estimated error rate.

        Args:
            estimated_qber: The estimated QBER from the key sample.

        Returns:
            The calculated initial block size.
        """
        if estimated_qber <= 0:
            return 16  # Fallback for a zero-error scenario
        return max(4, ceil(0.73 / estimated_qber))
