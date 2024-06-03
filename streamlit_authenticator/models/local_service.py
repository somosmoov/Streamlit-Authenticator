"""
Script description: This module executes the logic for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- streamlit: Framework used to build pure Python web applications.
- typing: Module implementing standard typing notations for Python functions.
"""

from typing import Callable, Dict, List, Optional
import streamlit as st

from utilities.hasher import Hasher
from utilities.validator import Validator
from utilities.helpers import Helpers
from utilities.exceptions import (CredentialsError,
                                  ForgotError,
                                  LoginError,
                                  RegisterError,
                                  ResetError,
                                  UpdateError)

class LocalService:
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
        self.credentials = credentials
        if self.credentials['usernames']:
            self.credentials['usernames'] = {
                key.lower(): value
                for key, value in self.credentials['usernames'].items()
                }
            for username, _ in self.credentials['usernames'].items():
                if 'logged_in' not in self.credentials['usernames'][username]:
                    self.credentials['usernames'][username]['logged_in'] = False
                if 'failed_login_attempts' not in self.credentials['usernames'][username]:
                    self.credentials['usernames'][username]['failed_login_attempts'] = 0
                if not Hasher._is_hash(self.credentials['usernames'][username]['password']):
                    self.credentials['usernames'][username]['password'] = \
                        Hasher._hash(self.credentials['usernames'][username]['password'])
        else:
            self.credentials['usernames'] = {}
        self.pre_authorized = pre_authorized
        self.validator = validator if validator is not None else Validator()
        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None
    def _check_captcha(self, captcha_name: str, entered_captcha: Optional[str]=None):
        """
        Checks the validity of the entered captcha.

        Parameters
        ----------
        captcha_name: str
            Name of the generated captcha stored in the session state.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.
        """
        if entered_captcha or entered_captcha == '':
            if entered_captcha != st.session_state[captcha_name]:
                raise RegisterError('Captcha entered incorrectly')
            del st.session_state[captcha_name]
    def check_credentials(self, username: str, password: str,
                          max_concurrent_users: Optional[int]=None,
                          max_login_attempts: Optional[int]=None,
                          entered_captcha: Optional[str]=None) -> bool:
        """
        Checks the validity of the entered credentials.

        Parameters
        ----------
        username: str
            The entered username.
        password: str
            The entered password.
        max_concurrent_users: int, optional
            Maximum number of users allowed to login concurrently.
        max_login_attempts: int, optional
            Maximum number of failed login attempts a user can make.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        bool
            Validity of the entered credentials.
        """
        self._check_captcha('login_captcha', entered_captcha)
        if isinstance(max_concurrent_users, int) and self._count_concurrent_users() > \
            max_concurrent_users - 1:
            raise LoginError('Maximum number of concurrent users exceeded')
        if username not in self.credentials['usernames']:
            return False
        if isinstance(max_login_attempts, int) and \
            self.credentials['usernames'][username]['failed_login_attempts'] >= max_login_attempts:
            raise LoginError('Maximum number of login attempts exceeded')
        try:
            if Hasher.check_pw(password, self.credentials['usernames'][username]['password']):
                return True
            self._record_failed_login_attempts(username)
            return False
        except (TypeError, ValueError) as e:
            print(e)
        return False
    def _count_concurrent_users(self) -> int:
        """
        Counts the number of users logged in concurrently.

        Returns
        -------
        int
            Number of users logged in concurrently.
        """
        concurrent_users = 0
        for username, _ in self.credentials['usernames'].items():
            if self.credentials['usernames'][username]['logged_in']:
                concurrent_users += 1
        return concurrent_users
    def _credentials_contains_value(self, value: str) -> bool:
        """
        Checks to see if a value is present in the credentials dictionary.

        Parameters
        ----------
        value: str
            Value being checked.

        Returns
        -------
        bool
            Presence/absence of the value, 
            True: value present, 
            False value absent.
        """
        return any(value in d.values() for d in self.credentials['usernames'].values())
    def execute_login(self, username: Optional[str]=None, token: Optional[Dict[str, str]]=None):
        """
        Executes login by setting authentication status to true and adding the user's
        username and name to the session state.

        Parameters
        ----------
        username: str, optional
            The username of the user being logged in.
        token: dict, optional
            The re-authentication cookie to get the username from.
        """
        if username:
            st.session_state['username'] = username
            st.session_state['name'] = self.credentials['usernames'][username]['name']
            st.session_state['authentication_status'] = True
            self._record_failed_login_attempts(username, reset=True)
            self.credentials['usernames'][username]['logged_in'] = True
        elif token:
            if not token['username'] in self.credentials['usernames']:
                raise LoginError('User not authorized')
            st.session_state['username'] = token['username']
            st.session_state['name'] = self.credentials['usernames'][token['username']]['name']
            st.session_state['authentication_status'] = True
            self.credentials['usernames'][token['username']]['logged_in'] = True
    def logout(self):
        """
        Clears the cookie and session state variables associated with the logged in user.
        """
        self.credentials['usernames'][st.session_state['username']]['logged_in'] = False
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None
    def forgot_password(self, username: str, callback: Optional[Callable]=None) -> tuple:
        """
        Creates a new random password for the user.

        Parameters
        ----------
        username: str
            Username associated with the forgotten password.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username of the user. 
        str
            Email of the user.
        str
            New random password of the user.
        """
        if username in self.credentials['usernames']:
            if callback:
                callback({'username': username})
            return (username, self._get_credentials()[username]['email'],
                    self._set_random_password(username))
        return False, None, None
    def forgot_username(self, email: str, callback: Optional[Callable]=None) -> tuple:
        """
        Gets the forgotten username of a user.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        """
        if callback:
            callback({'email': email})
        return self._get_username('email', email), email
    def _get_username(self, key: str, value: str) -> str:
        """
        Gets the username based on a provided entry.

        Parameters
        ----------
        key: str
            Name of the credential to query i.e. "email".
        value: str
            Value of the queried credential i.e. "jsmith@gmail.com".

        Returns
        -------
        str
            Username associated with the given key, value pair i.e. "jsmith".
        """
        for username, values in self.credentials['usernames'].items():
            if values[key] == value:
                return username
        return False
    def _get_credentials(self) -> dict:
        """
        Gets the user credentials dictionary.

        Returns
        -------
        dict
            User credentials dictionary.
        """
        return self.credentials['usernames']
    def _record_failed_login_attempts(self, username: str, reset: bool=False):
        """
        Records the number of failed login attempts for a given username.
        
        Parameters
        ----------
        reset: bool            
            Reset failed login attempts option, 
            True: number of failed login attempts for the user will be reset to 0, 
            False: number of failed login attempts for the user will be incremented.
        """
        if reset:
            self.credentials['usernames'][username]['failed_login_attempts'] = 0
        else:
            self.credentials['usernames'][username]['failed_login_attempts'] += 1
    def _register_credentials(self, username: str, name: str, password: str, email: str):
        """
        Adds the new user's information to the credentials dictionary.

        Parameters
        ----------
        username: str
            Username of the new user.
        name: str
            Name of the new user.
        password: str
            Password of the new user.
        email: str
            Email of the new user.
        """
        self.credentials['usernames'][username] = \
            {'name': name, 'password': Hasher([password]).generate()[0], 'email': email,
             'logged_in': False}
    def register_user(self, new_name: str, new_email: str, new_username: str,
                      new_password: str, pre_authorization: bool,
                      callback: Optional[Callable]=None) -> tuple:
        """
        Registers a new user's name, username, password, and email.

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
        pre-authorization: bool
            Pre-authorization requirement, 
            True: user must be pre-authorized to register, 
            False: any user can register.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        str
            Email of the new user.
        str
            Username of the new user.
        str
            Name of the new user.
        """
        if self._credentials_contains_value(new_email):
            raise RegisterError('Email already taken')
        if new_username in self.credentials['usernames']:
            raise RegisterError('Username already taken')
        if callback:
            callback({'new_name': new_name, 'new_email': new_email,
                      'new_username': new_username})
        if pre_authorization:
            if new_email in self.pre_authorized['emails']:
                self._register_credentials(new_username, new_name, new_password, new_email)
                self.pre_authorized['emails'].remove(new_email)
                return new_email, new_username, new_name
            raise RegisterError('User not pre-authorized to register')
        self._register_credentials(new_username, new_name, new_password, new_email)
        return new_email, new_username, new_name
    def _set_random_password(self, username: str) -> str:
        """
        Updates the credentials dictionary with the user's hashed random password.

        Parameters
        ----------
        username: str
            Username of the user to set the random password for.

        Returns
        -------
        str
            New plain text password that should be transferred to the user securely.
        """
        random_password = Helpers.generate_random_pw()
        self.credentials['usernames'][username]['password'] = \
            Hasher([random_password]).generate()[0]
        return random_password
    def _update_entry(self, username: str, key: str, value: str):
        """
        Updates the credentials dictionary with the user's updated entry.

        Parameters
        ----------
        username: str
            Username of the user to update the entry for.
        key: str
            Updated entry key i.e. "email".
        value: str
            Updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials['usernames'][username][key] = value
    def _update_password(self, username: str, password: str):
        """
        Updates the credentials dictionary with the user's hashed reset password.

        Parameters
        ----------
        username: str
            Username of the user to update the password for.
        password: str
            Updated plain text password.
        """
        self.credentials['usernames'][username]['password'] = Hasher([password]).generate()[0]
