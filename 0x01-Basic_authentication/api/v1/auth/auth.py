#!/usr/bin/env python3
"""
Auth
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
    Authentication class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if authentication is required
        """
        if path is None or excluded_paths is None or \
                len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path += '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*') and \
               path.startswith(excluded_path[:-1]):
                return False
            elif path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Return authorization header
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        else:
            return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Return current user
        """
        return None
