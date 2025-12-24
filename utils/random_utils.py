import os

def generate_iv(block_size: int) -> bytes:
    """
    Generate a cryptographically secure random IV.
    """
    return os.urandom(block_size)
