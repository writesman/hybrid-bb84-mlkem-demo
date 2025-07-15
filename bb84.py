import random
import hashlib
import base64
from dataclasses import dataclass
from qunetsim.components import Host, Network
from qunetsim.objects import Qubit
from math import ceil
from typing import Any


@dataclass
class CascadePassParitiesMessage:
    """Message containing all parities for all blocks in a pass."""
    parities: list[int]

@dataclass
class CascadeMismatchIndicesMessage:
    """Message containing the indices of blocks with parity mismatches."""
    mismatch_indices: list[int]


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
    KEY_CHECK_RATIO: float = 0.5  # Amount of the sifted key to compare
    KEY_LENGTH: int = 64
    MAX_QBER: float = 0.15  # Max tolerable QBER
    NETWORK_TIMEOUT: int = 20  # Wait time in seconds

    # Protocol Entry Points

    @staticmethod
    def alice_protocol(alice: Host, receiver_id: str, eavesdropper_present: bool = False) -> bytes | None:
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
        alice.send_classical(receiver_id, BasesMessage(bases=alice_bases), await_ack=True)
        bob_bases: list[str] = BB84._receive_classical(alice, receiver_id, BasesMessage).bases
        sifted_key_indices: list[int] = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key: list[int] = [alice_bits[i] for i in sifted_key_indices]
        if not sifted_key:
            raise BB84ProtocolError()

        # Step 4: Perform error checking by comparing a sample of the key
        num_samples: int = ceil(len(sifted_key) * BB84.KEY_CHECK_RATIO)
        sample_indices: list[int] = sorted(random.sample(range(len(sifted_key)), num_samples))
        sample_values: list[int] = [sifted_key[i] for i in sample_indices]
        alice.send_classical(receiver_id, SampleInfoMessage(indices=sample_indices, values=sample_values),
                             await_ack=False)
        estimated_qber: float = BB84._receive_classical(alice, receiver_id, QBERMessage).qber
        if estimated_qber > BB84.MAX_QBER:
            raise BB84ProtocolError()

        # Step 5: Perform error reconciliation (Cascade)
        noisy_key: list[int] = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        reconciled_key: list[int] = BB84._cascade_protocol(alice, receiver_id, True, noisy_key, estimated_qber)

        alice.send_classical(receiver_id, reconciled_key, await_ack=False)

        # Step 6: Perform privacy amplification and return the final key
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def bob_protocol(bob: Host, sender_id: str, simulated_qber: float = 0.0) -> bytes | None:
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
        alice_bases: list[str] = BB84._receive_classical(bob, sender_id, BasesMessage).bases
        bob.send_classical(sender_id, BasesMessage(bases=bob_bases), await_ack=False)
        sifted_key_indices: list[int] = [i for i in range(BB84.KEY_LENGTH) if alice_bases[i] == bob_bases[i]]
        sifted_key: list[int] = [bob_measured_bits[i] for i in sifted_key_indices]
        if not sifted_key:
            raise BB84ProtocolError()

        # Step 4: Calculate the error rate
        sample_info = BB84._receive_classical(bob, sender_id, SampleInfoMessage)
        sample_indices = sample_info.indices
        sample_values = sample_info.values

        mismatches: int = sum(1 for i, index in enumerate(sample_indices) if sifted_key[index] != sample_values[i])
        estimated_qber: float = (mismatches / len(sample_indices)) if sample_indices else 0.0
        bob.send_classical(sender_id, QBERMessage(qber=estimated_qber), await_ack=False)
        if estimated_qber > BB84.MAX_QBER:
            raise BB84ProtocolError()

        # Step 5: Perform error reconciliation (Cascade)
        noisy_key: list[int] = [sifted_key[i] for i in range(len(sifted_key)) if i not in sample_indices]
        reconciled_key: list[int] = BB84._cascade_protocol(bob, sender_id, False, noisy_key, estimated_qber)

        alice = bob.get_next_classical(sender_id, wait=BB84.NETWORK_TIMEOUT).content

        if alice == reconciled_key:
            print("Sucess")
        else:
            print("Fails")

        # Step 6: Perform privacy amplification and return the final key
        return BB84._privacy_amplification(reconciled_key)

    @staticmethod
    def eve_protocol(eve: Host, sender_id: str, receiver_id: str) -> None:
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
    def _cascade_protocol(host: Host, partner_id: str, is_alice: bool, key: list[int], estimated_qber: float,
                          seed: int = 42, max_passes: int = 4) -> list[int]:
        """
        Performs the Cascade error reconciliation protocol.

        This is a unified function for both Alice (the initiator) and Bob (the responder).
        The 'is_alice' flag determines the role and order of communication.
        """
        working_key = key.copy()
        key_length = len(working_key)

        for pass_num in range(max_passes):
            # --- 1. Block Creation and Shuffling (Identical for both parties) ---
            block_size = BB84._compute_initial_block_size(estimated_qber) * (2 ** pass_num)
            if block_size > key_length:
                block_size = key_length
            if block_size < 2:  # A block must have at least 2 bits to find an error
                block_size = 2

            indices = list(range(key_length))
            random.seed(seed + pass_num)  # Use a shared seed to get the same permutation
            random.shuffle(indices)

            # Create blocks, dropping any remainder
            blocks = [indices[i:i + block_size] for i in range(0, key_length, block_size) if
                      i + block_size <= key_length]
            if not blocks:
                continue

            my_parities = [sum(working_key[i] for i in block) % 2 for block in blocks]

            # --- 2. Parity Exchange to Find Mismatched Blocks ---
            if is_alice:
                # Alice sends her parities and receives back the indices of mismatched blocks.
                host.send_classical(partner_id, CascadePassParitiesMessage(parities=my_parities))
                mismatch_indices = BB84._receive_classical(host, partner_id,
                                                           CascadeMismatchIndicesMessage).mismatch_indices
            else:
                # Bob receives Alice's parities, compares them to his own, and sends back mismatch indices.
                their_parities = BB84._receive_classical(host, partner_id, CascadePassParitiesMessage).parities
                mismatch_indices = [i for i, block in enumerate(blocks) if my_parities[i] != their_parities[i]]
                host.send_classical(partner_id, CascadeMismatchIndicesMessage(mismatch_indices=mismatch_indices))

            mismatched_blocks = [blocks[i] for i in mismatch_indices]

            # --- 3. Binary Search to Find and Correct Errors ---
            for block in mismatched_blocks:
                search_block = block.copy()
                while len(search_block) > 1:
                    mid = len(search_block) // 2
                    left, right = search_block[:mid], search_block[mid:]
                    my_left_parity = sum(working_key[i] for i in left) % 2

                    if is_alice:
                        # Alice sends the parity of her left sub-block and learns if it matched Bob's.
                        host.send_classical(partner_id, CascadeSubParityMessage(parity=my_left_parity))
                        is_mismatch = BB84._receive_classical(host, partner_id, CascadeSubMismatchMessage).mismatch
                    else:
                        # Bob receives Alice's sub-parity, compares it, and reports if there's a mismatch.
                        alice_left_parity = BB84._receive_classical(host, partner_id, CascadeSubParityMessage).parity
                        is_mismatch = (my_left_parity != alice_left_parity)
                        host.send_classical(partner_id, CascadeSubMismatchMessage(mismatch=is_mismatch))

                    search_block = left if is_mismatch else right

                # Bob is the one to correct the bit, as Alice's key is the reference.
                if not is_alice and search_block:
                    error_index = search_block[0]
                    working_key[error_index] ^= 1  # Flip the bit

            # --- 4. Final Hash Check to Confirm Reconciliation ---
            my_hash = hashlib.sha256("".join(map(str, working_key)).encode()).digest()

            if is_alice:
                # Alice sends her hash and waits for confirmation of a match.
                host.send_classical(partner_id, KeyHashMessage(key_hash=my_hash))
                is_match = BB84._receive_classical(host, partner_id, KeyHashMatchMessage).is_match
            else:
                # Bob receives Alice's hash, compares it to his, and reports the result.
                their_hash = BB84._receive_classical(host, partner_id, KeyHashMessage).key_hash
                is_match = (my_hash == their_hash)
                host.send_classical(partner_id, KeyHashMatchMessage(is_match=is_match))

            if is_match:
                # Keys are reconciled, exit the loop.
                return working_key

        # If loops complete without a match, the protocol has failed.
        raise BB84ProtocolError("Cascade failed to reconcile keys after all passes.")

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
        if estimated_qber <= 0:
            return 16  # Fallback for a zero-error scenario
        return max(4, ceil(0.73 / estimated_qber))


def run_bb84(simulated_qber: float = 0.0, eavesdropper_present: bool = False) -> None:
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
        # {
        #     "description": "With an eavesdropper (should fail)",
        #     "simulated_qber": 0.0,
        #     "eavesdropper_present": True
        # },
    ]

    for i, scenario in enumerate(scenarios):
        print(f"===== Scenario {i + 1}: {scenario['description']} =====")
        run_bb84(simulated_qber=scenario['simulated_qber'], eavesdropper_present=scenario['eavesdropper_present'])


if __name__ == '__main__':
    main()
