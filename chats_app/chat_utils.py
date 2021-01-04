import json


def construct_message_packet(content: str,
                             message_type: str,
                             recipient: str = "Broadcast",
                             public_key: str = None,
                             encrypted: bool = False) -> bytes:
    """
    Constructs a packet with "headers" to send out via the socket.
    """
    message = json.dumps({"Content": content,
                          "Type": message_type,
                          "Recipient": recipient,
                          "Public Key": public_key,
                          "Encrypted": encrypted})
    return message.encode("utf-8")


def load_message_packet(received_packet: bytes) -> dict:
    """
    Takes a received packet and turns it into a dictionary of key/value
    pairs.
    """
    packet_dict = json.loads(received_packet.decode())
    return packet_dict