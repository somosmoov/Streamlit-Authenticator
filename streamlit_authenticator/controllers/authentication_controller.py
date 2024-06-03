"""
Script description: This module executes the logic for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- streamlit: Framework used to build pure Python web applications.
- typing: Module implementing standard typing notations for Python functions.
"""

from typing import Callable, Dict, List, Optional
import streamlit as st

from models import LocalService

from utilities.hasher import Hasher
from utilities.validator import Validator
from utilities.helpers import Helpers
from utilities.exceptions import (CredentialsError,
                                  ForgotError,
                                  LoginError,
                                  RegisterError,
                                  ResetError,
                                  UpdateError)

class AuthenticationController:
    """
    This class will execute the logic for the login, logout, register user, reset password, 
    forgot password, forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, pre_authorized: Optional[List[str]]=None,
                 validator: Optional[Validator]=None):
        """
        Create a new instance of "AuthenticationHandler".

        Parameters
        ----------
        credentials: dict
            Dictionary of usernames, names, passwords, emails, and other user data.
        pre-authorized: list, optional
            List of emails of unregistered users who are authorized to register.        
        validator: Validator, optional
            Validator object that checks the validity of the username, name, and email fields.
        """
        self.authentication_service = LocalService(credentials,
                                                   pre_authorized,
                                                   validator)
        self.validator = Validator()
    def _check_captcha(self, captcha_name: str, exception: Exception, entered_captcha: str):
        """
        Checks the validity of the entered captcha.

        Parameters
        ----------
        captcha_name: str
            Name of the generated captcha stored in the session state.
        exception: Exception
            Type of exception to be raised.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.
        """
        if Helpers.check_captcha(captcha_name, entered_captcha):
            del st.session_state[captcha_name]
        else:
            raise exception('Captcha entered incorrectly')
    def forgot_password(self, username: str, callback: Optional[Callable]=None,
                        entered_captcha: Optional[str]=None) -> tuple:
        """
        Controls the request to create a new random password for the user.

        Parameters
        ----------
        username: str
            Username associated with the forgotten password.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        str
            New random password of the user.
        """
        username = username.lower().strip()
        entered_captcha = entered_captcha.strip()
        self._check_captcha('forgot_password_captcha', ForgotError, entered_captcha)
        if not self.validator.validate_length(username, 1):
            raise ForgotError('Username not provided')
        return self.authentication_service.forgot_password(username, callback)
    def forgot_username(self, email: str, callback: Optional[Callable]=None,
                        entered_captcha: Optional[str]=None) -> tuple:
        """
        Controls the request to get the forgotten username of a user.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        """
        email = email.strip()
        entered_captcha = entered_captcha.strip()
        self._check_captcha('forgot_username_captcha', ForgotError, entered_captcha)
        if not self.validator.validate_length(email, 1):
            raise ForgotError('Email not provided')
        return self.authentication_service.forgot_username(email, callback)
    #def login(self) -> 
    def logout(self):
        """
        Controls the request to logout a user.

        """
        self.authentication_service.logout()
    def register_user(self, new_name: str, new_email: str, new_username: str,
                      new_password: str, new_password_repeat: str, pre_authorization: bool,
                      domains: Optional[List[str]]=None, callback: Optional[Callable]=None,
                      entered_captcha: Optional[str]=None) -> tuple:
        """
        Controls the request to register a new user's name, username, password, and email.

        Parameters
        ----------
        new_name: str
            Name of the new user.
        new_email: str
            Email of the new user.
        new_username: str
            Username of the new user.
        new_password: str
            Password of the new user.
        new_password_repeat: str
            Repeated password of the new user.
        pre-authorization: bool
            Pre-authorization requirement, 
            True: user must be pre-authorized to register, 
            False: any user can register.
        domains: list, optional
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: the required list of domains, 
            None: any domain is allowed.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        str
            Email of the new user.
        str
            Username of the new user.
        str
            Name of the new user.
        """
        new_name = new_name.strip()
        new_email = new_email.strip()
        new_username = new_username.lower().strip()
        new_password = new_password.strip()
        new_password_repeat = new_password_repeat.strip()
        if not self.validator.validate_name(new_name):
            raise RegisterError('Name is not valid')
        if not self.validator.validate_email(new_email):
            raise RegisterError('Email is not valid')
        if domains:
            if new_email.split('@')[1] not in ' '.join(domains):
                raise RegisterError('Email not allowed to register')
        if not self.validator.validate_username(new_username):
            raise RegisterError('Username is not valid')
        if not self.validator.validate_length(new_password, 1) \
            or not self.validator.validate_length(new_password_repeat, 1):
            raise RegisterError('Password/repeat password fields cannot be empty')
        if new_password != new_password_repeat:
            raise RegisterError('Passwords do not match')
        if not self.validator.validate_password(new_password):
            raise RegisterError('Password does not meet criteria')
        if pre_authorization:
            if not self.authentication_service.pre_authorized:
                raise RegisterError('Pre-authorization argument must not be None')
        entered_captcha = entered_captcha.strip()
        self._check_captcha('register_user_captcha', RegisterError, entered_captcha)
        return self.authentication_service.register_user(new_name, new_email, new_username,
                                                         new_password, pre_authorization,
                                                         callback)
    def reset_password(self, username: str, password: str, new_password: str,
                       new_password_repeat: str) -> bool:
        """
        Validates the user's current password and subsequently saves their new password to the 
        credentials dictionary.

        Parameters
        ----------
        username: str
            Username of the user.
        password: str
            Current password of the user.
        new_password: str
            New password of the user.
        new_password_repeat: str
            Repeated new password of the user.

        Returns
        -------
        bool
            State of resetting the password, 
            True: password reset successfully.
        """
        if not self.check_credentials(username, password):
            raise CredentialsError('password')
        if not self.validator.validate_length(new_password, 1):
            raise ResetError('No new password provided')
        if new_password != new_password_repeat:
            raise ResetError('Passwords do not match')
        if password == new_password:
            raise ResetError('New and current passwords are the same')
        if not self.validator.validate_password(new_password):
            raise ResetError('Password does not meet criteria')
        self._update_password(username, new_password)
        self._record_failed_login_attempts(username, reset=True)
        return True
    def update_user_details(self, new_value: str, username: str, field: str) -> bool:
        """
        Validates the user's updated name or email and subsequently modifies it in the
        credentials dictionary.

        Parameters
        ----------
        new_value: str
            New value for the name or email.
        username: str
            Username of the user.
        field: str
            Field to update i.e. name or email.

        Returns
        -------
        bool
            State of updating the user's detail, 
            True: details updated successfully.
        """
        if field == 'name':
            if not self.validator.validate_name(new_value):
                raise UpdateError('Name is not valid')
        if field == 'email':
            if not self.validator.validate_email(new_value):
                raise UpdateError('Email is not valid')
            if self._credentials_contains_value(new_value):
                raise UpdateError('Email already taken')
        if new_value != self.credentials['usernames'][username][field]:
            self._update_entry(username, field, new_value)
            if field == 'name':
                st.session_state['name'] = new_value
            return True
        else:
            raise UpdateError('New and current values are the same')
