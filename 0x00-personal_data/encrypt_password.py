#!/usr/bin/env python3
"""
encryption module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes the password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates hash
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
