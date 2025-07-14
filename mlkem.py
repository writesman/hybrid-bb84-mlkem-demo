from quantcrypt.kem import MLKEM_1024
from qunetsim.components import Host
import base64
from typing import Any


class MLKEMProtocolError(Exception):
    """
    Custom exception for errors during the KEM protocol.
    """
    pass


class MLKEM:
    """
    A class for ML-KEM-1024 key exchange using QuNetSim.
    """

    # Class-level constants
    KEM = MLKEM_1024()
    NETWORK_TIMEOUT: int = 20

    @staticmethod
    def encapsulate(host: Host, receiver_id: str) -> bytes:
        """
        Sender's side of KEM: gets a public key to create and send a ciphertext.

        Args:
            host: The sending QuNetSim host.
            receiver_id: The ID of the receiving host.

        Returns:
            The URL-safe base64 encoded shared secret.

        Raises:
            MLKEMProtocolError: If the protocol fails.
        """
        public_key = MLKEM._receive_classical(host, receiver_id, "PUBLIC_KEY")
        ciphertext, shared_secret = MLKEM.KEM.encaps(public_key)
        host.send_classical(receiver_id, ("CIPHERTEXT", ciphertext), await_ack=True)
        return base64.urlsafe_b64encode(shared_secret)

    @staticmethod
    def decapsulate(host: Host, sender_id: str) -> bytes:
        """
        Receiver's side of KEM: sends a public key and uses the response to derive the shared secret.

        Args:
            host: The receiving QuNetSim host.
            sender_id: The ID of the sending host.

        Returns:
            The URL-safe base64 encoded shared secret.

        Raises:
            MLKEMProtocolError: If the protocol fails.
        """
        public_key, secret_key = MLKEM.KEM.keygen()
        host.send_classical(sender_id, ("PUBLIC_KEY", public_key), await_ack=True)
        ciphertext = MLKEM._receive_classical(host, sender_id, "CIPHERTEXT")
        shared_secret = MLKEM.KEM.decaps(secret_key, ciphertext)
        return base64.urlsafe_b64encode(shared_secret)

    @staticmethod
    def _receive_classical(host: Host, sender_id: str, expected_type: str) -> Any:
        """
        Safely receives and unpacks a specific classical message.

        Args:
            host: The QuNetSim host receiving the message.
            sender_id: The ID of the expected sender.
            expected_type: The expected message type string.

        Returns:
            The message payload.

        Raises:
            MLKEMProtocolError: On timeout or if the message is malformed/unexpected.
        """
        message = host.get_next_classical(sender_id, wait=MLKEM.NETWORK_TIMEOUT)

        if message is None:
            raise MLKEMProtocolError(f"Timeout waiting for '{expected_type}' from {sender_id}.")

        try:
            message_type, payload = message.content
            if message_type != expected_type:
                raise MLKEMProtocolError(f"Received '{message_type}', expected '{expected_type}'.")
            return payload
        except (ValueError, TypeError):
            raise MLKEMProtocolError("Received a malformed message.")
