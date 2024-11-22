#!/usr/bin/env python3
"""
a module that contains a function that encrypts passwords
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with a salt.

    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The salted, hashed password as a byte string.
    """
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates if a given password matches a hashed password.

    Args:
        hashed_password (bytes): The hashed password to validate against.
        password (str): The plain text password to validate.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    # Compare the provided password with the hashed password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
