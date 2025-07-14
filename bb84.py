import random
import hashlib
import base64
from dataclasses import dataclass
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit, Logger
from math import ceil
from typing import Any

Logger.DISABLED = True


# For Step 3: Basis Exchange
@dataclass
class BasesMessage:
    """Message containing a list of bases for sifting."""
    bases: list[str]


@dataclass
class SampleInfoMessage:
    """Message containing the indices and values for the key sample."""
    indices: list[int]
    values: list[int]


@dataclass
class QBERMessage:
    """Message containing the estimated Quantum Bit Error Rate (QBER)."""
    qber: float


@dataclass
class CascadeBlockMessage:
    """Message for a block of key indices and its corresponding parity."""
    block: list[int]
    parity: int

@dataclass
class CascadeMismatchMessage:
    """Message indicating if a parity mismatch was found in a block."""
    mismatch: bool

@dataclass
class CascadeSubParityMessage:
    """Message for the parity of a sub-block during binary search."""
    parity: int

@dataclass
class CascadeSubMismatchMessage:
    """Message indicating if a parity mismatch was found in a sub-block."""
    mismatch: bool

@dataclass
class KeyHashMessage:
    """Message containing the hash of a party's reconciled key."""
    key_hash: bytes

@dataclass
class KeyHashMatchMessage:
    """Message confirming whether the key hashes match."""
    is_match: bool

class BB84ProtocolError(Exception):
    """
    Custom exception for errors during the KEM protocol.
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
        Executes the full BB84 protocol from Alice's perspective.

        Args:
            alice: The Host object for Alice.
            receiver_id: The network ID of the intended receiver (Bob).
            eavesdropper_present: Waits for qubit receipt acknowledgements if True

        Returns:
            The final, secure key as a bytes object, or None if the protocol fails.
        """
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
        message = BasesMessage(bases=alice_bases)
        alice.send_classical(receiver_id, message, await_ack=True)

        bob_bases: list[str] = BB84._receive_classical(alice, receiver_id, BasesMessage)
        sifted_key_indices: list[int] = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key: list[int] = [alice_bits[i] for i in sifted_key_indices]
        if not sifted_key:
            raise BB84ProtocolError()

        # Step 4: Perform error checking by comparing a sample of the key
        num_samples: int = ceil(len(sifted_key) * BB84.KEY_CHECK_RATIO)
        sample_indices: list[int] = sorted(random.sample(range(len(sifted_key)), num_samples))
        sample_values: list[int] = [sifted_key[i] for i in sample_indices]

        message = SampleInfoMessage(indices=sample_indices, values=sample_values)
        alice.send_classical(receiver_id, message, await_ack=False)

        estimated_qber: float = BB84._receive_classical(alice, receiver_id, QBERMessage)
        if estimated_qber > BB84.MAX_QBER:
            raise BB84ProtocolError()

        # Step 5: Perform error reconciliation (Cascade)
        noisy_key: list[int] = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        reconciled_key: list[int] | None = BB84._alice_cascade_protocol(alice, receiver_id, noisy_key, estimated_qber)

        # Step 6: Perform privacy amplification and return the final key
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def bob_protocol(bob: Host, sender_id: str, simulated_qber: float = 0.0) -> bytes | None:
        """
        Executes the full BB84 protocol from Bob's perspective.

        Args:
            bob: The Host object for Bob.
            sender_id: The network ID of the sender (Alice or Eve).
            simulated_qber: The QBER to simulate for channel noise.

        Returns:
            The final, secure key as a bytes object, or None if the protocol fails.
        """
        # Step 1: Generate random bases for measurement
        bob_bases: list[str] = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        # Step 2: Receive and measure qubits
        bob_measured_bits: list[int] = []
        for i in range(BB84.KEY_LENGTH):
            qubit = bob.get_qubit(sender_id, wait=BB84.NETWORK_TIMEOUT)
            if qubit is None:
                raise BB84ProtocolError()
            if simulated_qber > 0 and random.random() < simulated_qber:
                random.choice([qubit.X(), qubit.Y(), qubit.Z()])
            if bob_bases[i] == 'X':
                qubit.H()
            bob_measured_bits.append(qubit.measure())

        # Step 3: Compare bases with Alice to create the sifted key
        alice_bases: list[str] = BB84._receive_classical(bob, sender_id, BasesMessage)

        message = BasesMessage(bases=bob_bases)
        bob.send_classical(sender_id, message, await_ack=False)

        sifted_key_indices: list[int] = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key: list[int] = [bob_measured_bits[i] for i in sifted_key_indices]
        if not sifted_key:
            raise BB84ProtocolError()

        # Step 4: Calculate the error rate
        sample_indices, sample_values = BB84._receive_classical(bob, sender_id, SampleInfoMessage)
        mismatches: int = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])
        estimated_qber: float = (mismatches / len(sample_indices)) if sample_indices else 0.0

        message = QBERMessage(qber=estimated_qber)
        bob.send_classical(sender_id, message, await_ack=False)

        if estimated_qber > BB84.MAX_QBER:
            raise BB84ProtocolError()

        # Step 5: Perform error reconciliation (Cascade)
        noisy_key: list[int] = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        reconciled_key: list[int] | None = BB84._bob_cascade_protocol(bob, sender_id, noisy_key, estimated_qber)

        # Step 6: Perform privacy amplification and return the final key
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def eve_protocol(eve: Host, sender_id: str, receiver_id: str) -> None:
        """
        Executes an intercept-and-resend eavesdropping attack.

        Args:
            eve: The Host object for Eve.
            sender_id: The network ID of the original sender (Alice).
            receiver_id: The network ID of the intended receiver (Bob).
        """
        eve_bases: list[str] = [random.choice(['Z', 'X']) for _ in range(BB84.KEY_LENGTH)]

        for i in range(BB84.KEY_LENGTH):
            qubit = eve.get_qubit(sender_id, wait=BB84.NETWORK_TIMEOUT)
            if qubit is None:
                raise BB84ProtocolError()
            if eve_bases[i] == 'X':
                qubit.H()
            measured_bit = qubit.measure()

            new_qubit = Qubit(eve)
            if measured_bit == 1:
                new_qubit.X()
            if eve_bases[i] == 'X':
                new_qubit.H()
            eve.send_qubit(receiver_id, new_qubit, await_ack=True)

        # TODO: implement forward_classical

        # alice_bases: list[str] = BB84._receive_classical(eve, sender_id, "BASES")
        # eve.send_classical(receiver_id, ("BASES", alice_bases), await_ack=True)
        #
        # bob_bases: list[str] = BB84._receive_classical(eve, receiver_id, "BASES")
        # eve.send_classical(sender_id, ("BASES", bob_bases), await_ack=True)
        #
        # sample_indices, sample_values = BB84._receive_classical(eve, sender_id, "SAMPLE_INFO")
        # eve.send_classical(receiver_id, ("SAMPLE_INFO", sample_indices, sample_values), await_ack=True)
        #
        # error_rate = BB84._receive_classical(eve, receiver_id, "ERROR_RATE")
        # eve.send_classical(sender_id, ("ERROR_RATE", error_rate))

    # Cascade Protocol Logic

    @staticmethod
    def _alice_cascade_protocol(alice: Host, bob_id: str, noisy_key: list[int], estimated_qber: float, seed: int = 42,
                                max_passes: int = 10) -> list[int] | None:
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

                message = CascadeBlockMessage(block=block, parity=alice_parity)
                alice.send_classical(bob_id, message, await_ack=True)

                mismatch: bool = BB84._receive_classical(alice, bob_id, CascadeMismatchMessage)
                if mismatch:
                    BB84._alice_cascade_binary_search(alice, bob_id, working_key, block)

            key_hash: bytes = hashlib.sha256("".join(map(str, working_key)).encode('utf-8')).digest()

            message = KeyHashMessage(key_hash=key_hash)
            alice.send_classical(bob_id, message, await_ack=True)

            is_match: bool = BB84._receive_classical(alice, bob_id, KeyHashMatchMessage)
            if is_match:
                return working_key

        raise BB84ProtocolError()

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
                block, alice_parity = BB84._receive_classical(bob, alice_id, CascadeBlockMessage)
                bob_parity: int = sum(working_key[i] for i in block) % 2
                mismatch: bool = (bob_parity != alice_parity)

                message = CascadeMismatchMessage(mismatch=mismatch)
                bob.send_classical(alice_id, message, await_ack=True)

                if mismatch:
                    BB84._bob_cascade_binary_search(bob, alice_id, working_key, block)

            key_hash: bytes = BB84._receive_classical(bob, alice_id, KeyHashMessage)
            bob_key_hash: bytes = hashlib.sha256("".join(map(str, working_key)).encode('utf-8')).digest()
            is_match: bool = (bob_key_hash == key_hash)

            message = KeyHashMatchMessage(is_match=is_match)
            bob.send_classical(alice_id, message, await_ack=True)

            if is_match:
                return working_key

        raise BB84ProtocolError()

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

            message = CascadeSubParityMessage(parity=left_parity)
            alice.send_classical(bob_id, message, await_ack=True)

            mismatch_in_left: bool = BB84._receive_classical(alice, bob_id, CascadeSubMismatchMessage)
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

            alice_left_parity: int = BB84._receive_classical(bob, alice_id, CascadeSubParityMessage)
            if alice_left_parity is None:
                return

            bob_left_parity: int = sum(key[i] for i in left) % 2
            mismatch_in_left: bool = (alice_left_parity != bob_left_parity)

            message = CascadeSubMismatchMessage(mismatch=mismatch_in_left)
            bob.send_classical(alice_id, message, await_ack=True)

            block = left if mismatch_in_left else block[mid:]

        error_index: int = block[0]
        key[error_index] ^= 1

    # Helper Functions

    @staticmethod
    def _receive_classical(host: Host, sender_id: str, expected_type: type) -> Any:
        """
        """
        message_object = host.get_next_classical(sender_id, wait=BB84.NETWORK_TIMEOUT)
        if message_object is None:
            raise BB84ProtocolError()

        content = message_object.content
        if not isinstance(content, expected_type):
            raise BB84ProtocolError()

        return content

    @staticmethod
    def _forward_classical_message(host: Host, sender_id: str, receiver_id: str) -> bool:
        pass

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
