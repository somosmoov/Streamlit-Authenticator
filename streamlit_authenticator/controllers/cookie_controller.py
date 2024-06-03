"""
Script description: This module controls requests made to the cookie service for password-less
re-authentication. 
"""

from models.cookie_service import CookieService

class CookieController:
    """
    This class will control all the requests made related to the re-authentication cookie, 
    including deleting, getting, and setting the cookie.
    """
    def __init__(self, cookie_name: str, cookie_key: str, cookie_expiry_days: float):
        """
        Create a new instance of "CookieController".

        Parameters
        ----------
        cookie_name: str
            Name of the cookie stored on the client's browser for password-less re-authentication.
        cookie_key: str
            Key to be used to hash the signature of the re-authentication cookie.
        cookie_expiry_days: float
            Number of days before the re-authentication cookie automatically expires on the client's 
            browser.
        """
        self.cookie_service = CookieService(cookie_name,
                                            cookie_key,
                                            cookie_expiry_days)
    def delete_cookie(self):
        """
        Deletes the re-authentication cookie.
        """
        self.cookie_service.delete_cookie()
    def get_cookie(self):
        """
        Gets the re-authentication cookie.

        Returns
        -------
        str
            Re-authentication cookie.
        """
        return self.cookie_service.get_cookie()
    def set_cookie(self):
        """
        Sets the re-authentication cookie.
        """
        self.cookie_service.set_cookie()
