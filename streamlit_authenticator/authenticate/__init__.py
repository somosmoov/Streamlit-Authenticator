"""
Script description: This module renders and invokes the logic for the
login, logout, register user, reset password, forgot password, forgot username,
and modify user details widgets. 

Libraries imported:
- time: Module implementing the sleep function.
- streamlit: Framework used to build pure Python web applications.
- typing: Module implementing standard typing notations for Python functions.
"""

import time
from typing import Dict, List, Optional
import streamlit as st

from utilities.helpers import Helpers
from utilities.validator import Validator
from utilities.exceptions import DeprecationError

from .cookie import CookieHandler
from .authentication import AuthenticationHandler

class Authenticate:
    """
    This class will create login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, cookie_name: str, cookie_key: str,
                 cookie_expiry_days: float=30.0, pre_authorized: Optional[List[str]]=None,
                 validator: Optional[Validator]=None):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        credentials: dict
            Dictionary of usernames, names, passwords, emails, and other user data.
        cookie_name: str
            Name of the re-authentication cookie stored on the client's browser for password-less 
            re-authentication.
        cookie_key: str
            Key to be used to hash the signature of the re-authentication cookie.
        cookie_expiry_days: float
            Number of days before the re-authentication cookie automatically expires on the client's 
            browser.
        pre-authorized: list
            List of emails of unregistered users who are authorized to register.        
        validator: Validator
            Validator object that checks the validity of the username, name, and email fields.
        """
        self.authentication_handler     =   AuthenticationHandler(credentials,
                                                                  pre_authorized,
                                                                  validator)
        self.cookie_handler             =   CookieHandler(cookie_name,
                                                          cookie_key,
                                                          cookie_expiry_days)
    def forgot_password(self, location: str='main', fields: Optional[Dict[str, str]]=None,
                        captcha: bool=False, clear_on_submit: bool=False,
                        key: Optional[str]=None) -> tuple:
        """
        Creates a forgot password widget.

        Parameters
        ----------
        location: str
            Location of the forgot password widget i.e. main or sidebar.
        fields: dict
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the forgot password widget, True: captcha required,
            False: captcha removed.
        clear_on_submit: bool
            Clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
        key: str
            Unique key provided to widgets to avoid duplicate WidgetID errors.

        Returns
        -------
        str
            Username associated with the forgotten password.
        str
            Email associated with the forgotten password.
        str
            New plain text password that should be transferred to the user securely.
        """
        if fields is None:
            fields = {'Form name':'Forgot password', 'Username':'Username', 'Submit':'Submit',
                      'Captcha':'Captcha'}
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until a future release
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been
                                   replaced with the 'fields' parameter. For further information 
                                   please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateforgot_password""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form('Forgot password', clear_on_submit=clear_on_submit,
                                          key=key)
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form('Forgot password',
                                                   clear_on_submit=clear_on_submit, key=key)

        forgot_password_form.subheader('Forget password' if 'Form name' not in fields
                                       else fields['Form name'], key=key)
        username = forgot_password_form.text_input('Username' if 'Username' not in fields
                                                   else fields['Username'],
                                                   key=key).lower().strip()
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_password_form.text_input('Captcha' if 'Captcha' not in fields
                                                              else fields['Captcha'],
                                                              key=key).strip()
            forgot_password_form.image(Helpers.generate_captcha('forgot_password_captcha'))
        if forgot_password_form.form_submit_button('Submit' if 'Submit' not in fields
                                                   else fields['Submit']):
            return self.authentication_handler.forgot_password(username, entered_captcha)
        return None, None, None
    def forgot_username(self, location: str='main', fields: Optional[Dict[str, str]]=None,
                        captcha: bool=False, clear_on_submit: bool=False,
                        key: Optional[str]=None) -> tuple:
        """
        Creates a forgot username widget.

        Parameters
        ----------
        location: str
            Location of the forgot username widget i.e. main or sidebar.
        fields: dict
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the forgot username widget, True: captcha required,
            False: captcha removed.
        clear_on_submit: bool
            Clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
        key: str
            Unique key provided to widgets to avoid duplicate WidgetID errors.

        Returns
        -------
        str
            Forgotten username that should be transferred to the user securely.
        str
            Email associated with the forgotten username.
        """
        if fields is None:
            fields = {'Form name':'Forgot username', 'Email':'Email', 'Submit':'Submit',
                     'Captcha':'Captcha'}
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until a future release
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter
                                   has been replaced with the 'fields' parameter. For further
                                   information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateforgot_username""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_username_form = st.form('Forgot username', clear_on_submit=clear_on_submit,
                                           key=key)
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form('Forgot username', clear_on_submit=clear_on_submit,
                                                   key=key)
        forgot_username_form.subheader('Forget username' if 'Form name' not in fields
                                       else fields['Form name'], key=key)
        email = forgot_username_form.text_input('Email' if 'Email' not in fields
                                                else fields['Email'], key=key).strip()
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_username_form.text_input('Captcha' if 'Captcha' not in fields
                                                              else fields['Captcha'],
                                                              key=key).strip()
            forgot_username_form.image(Helpers.generate_captcha('forgot_username_captcha'))
        if forgot_username_form.form_submit_button('Submit' if 'Submit' not in fields
                                                   else fields['Submit']):
            return self.authentication_handler.forgot_username(email, entered_captcha)
        return None, email
    def login(self, location: str='main', max_concurrent_users: Optional[int]=None,
              max_login_attempts: Optional[int]=None, fields: Optional[Dict[str, str]]=None,
              captcha: bool=False, clear_on_submit: bool=False, key: Optional[str]=None) -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        location: str
            Location of the logout button i.e. main, sidebar or unrendered.
        max_concurrent_users: int
            Maximum number of users allowed to login concurrently.
        max_login_attempts: int
            Maximum number of failed login attempts a user can make.
        fields: dict
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the login widget, True: captcha required,
            False: captcha removed.
        clear_on_submit: bool
            Clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
        key: str
            Unique key provided to widgets to avoid duplicate WidgetID errors.

        Returns
        -------
        str
            Name of the authenticated user.
        bool
            Status of authentication, None: no credentials entered, 
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        if fields is None:
            fields = {'Form name':'Login', 'Username':'Username', 'Password':'Password',
                      'Login':'Login', 'Captcha':'Captcha'}
        if location not in ['main', 'sidebar', 'unrendered']:
            # Temporary deprecation error to be displayed until a future release
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been
                                   replaced with the 'fields' parameter. For further information please 
                                   refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticatelogin""")
            # raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if not st.session_state['authentication_status']:
            token = self.cookie_handler.get_cookie()
            if token:
                self.authentication_handler.execute_login(token=token)
                time.sleep(0.7)
            if not st.session_state['authentication_status']:
                if location == 'main':
                    login_form = st.form('Login', clear_on_submit=clear_on_submit, key=key)
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login', clear_on_submit=clear_on_submit, key=key)
                elif location == 'unrendered':
                    return (st.session_state['name'], st.session_state['authentication_status'],
                        st.session_state['username'])
                login_form.subheader('Login' if 'Form name' not in fields else fields['Form name'],
                                     key=key)
                username = login_form.text_input('Username' if 'Username' not in fields
                                                 else fields['Username'], key=key).lower().strip()
                password = login_form.text_input('Password' if 'Password' not in fields
                                                 else fields['Password'], type='password',
                                                 key=key).strip()
                entered_captcha = None
                if captcha:
                    entered_captcha = login_form.text_input('Captcha' if 'Captcha' not in fields
                                                            else fields['Captcha'],
                                                            key=key).strip()
                    login_form.image(Helpers.generate_captcha('login_captcha'))
                if login_form.form_submit_button('Login' if 'Login' not in fields
                                                 else fields['Login']):
                    if self.authentication_handler.check_credentials(username,
                                                                     password,
                                                                     max_concurrent_users,
                                                                     max_login_attempts,
                                                                     entered_captcha):
                        self.authentication_handler.execute_login(username=username)
                        self.cookie_handler.set_cookie()
        return (st.session_state['name'], st.session_state['authentication_status'],
                st.session_state['username'])
    def logout(self, button_name: str='Logout', location: str='main', key: Optional[str]=None):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            Rendered name of the logout button.
        location: str
            Location of the logout button i.e. main, sidebar or unrendered.
        key: str
            Unique key to be used in multi-page applications.
        """
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if location == 'main':
            if st.button(button_name, key=key):
                self.authentication_handler.execute_logout()
                self.cookie_handler.delete_cookie()
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key=key):
                self.authentication_handler.execute_logout()
                self.cookie_handler.delete_cookie()
        elif location == 'unrendered':
            if st.session_state['authentication_status']:
                self.authentication_handler.execute_logout()
                self.cookie_handler.delete_cookie()
    def register_user(self, location: str='main', pre_authorization: bool=True,
                      domains: Optional[List[str]]=None, fields: Optional[Dict[str, str]]=None,
                      captcha: bool=True, clear_on_submit: bool=False,
                      key: Optional[str]=None) -> tuple:
        """
        Creates a register new user widget.

        Parameters
        ----------
        location: str
            Location of the register new user widget i.e. main or sidebar.
        pre-authorization: bool
            Pre-authorization requirement, True: user must be pre-authorized to register, 
            False: any user can register.
        domains: list
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: required list of domains, None: any domain is allowed.
        fields: dict
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the register user widget, True: captcha required,
            False: captcha removed.
        clear_on_submit: bool
            Clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
        key: str
            Unique key provided to widgets to avoid duplicate WidgetID errors.

        Returns
        -------
        str
            Email associated with the new user.
        str
            Username associated with the new user.
        str
            Name associated with the new user.
        """
        if fields is None:
            fields = {'Form name':'Register user', 'Email':'Email', 'Username':'Username',
                      'Password':'Password', 'Repeat password':'Repeat password',
                      'Register':'Register', 'Captcha':'Captcha'}
        if pre_authorization:
            if not self.authentication_handler.pre_authorized:
                raise ValueError("pre-authorization argument must not be None")
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until a future release
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has
                                   been replaced with the 'fields' parameter. For further
                                   information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateregister_user""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            register_user_form = st.form('Register user', clear_on_submit=clear_on_submit,
                                         key=key)
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user', clear_on_submit=clear_on_submit,
                                                 key=key)
        register_user_form.subheader('Register User' if 'Form name' not in fields
                                     else fields['Form name'], key=key)
        new_name = register_user_form.text_input('Name' if 'Name' not in fields
                                                 else fields['Name'], key=key).strip()
        new_email = register_user_form.text_input('Email' if 'Email' not in fields
                                                  else fields['Email'], key=key).strip()
        new_username = register_user_form.text_input('Username' if 'Username' not in fields
                                                     else fields['Username'],
                                                     key=key).lower().strip()
        new_password = register_user_form.text_input('Password' if 'Password' not in fields
                                                     else fields['Password'],
                                                     type='password', key=key).strip()
        new_password_repeat = register_user_form.text_input('Repeat password'
                                                            if 'Repeat password' not in fields
                                                            else fields['Repeat password'],
                                                            type='password', key=key).strip()
        entered_captcha = None
        if captcha:
            entered_captcha = register_user_form.text_input('Captcha' if 'Captcha' not in fields
                                                            else fields['Captcha'],
                                                            key=key).strip()
            register_user_form.image(Helpers.generate_captcha('register_user_captcha'))
        if register_user_form.form_submit_button('Register' if 'Register' not in fields
                                                 else fields['Register']):
            return self.authentication_handler.register_user(new_password, new_password_repeat,
                                                             pre_authorization, new_username,
                                                             new_name, new_email, entered_captcha,
                                                             domains)
        return None, None, None
    def reset_password(self, username: str, location: str='main',
                       fields: Optional[Dict[str, str]]=None, clear_on_submit: bool=False,
                       key: Optional[str]=None) -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        username: str
            Username of the user to reset the password for.
        location: str
            Location of the password reset widget i.e. main or sidebar.
        fields: dict
            Rendered names of the fields/buttons.
        clear_on_submit: bool
            Clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
        key: str
            Unique key provided to widgets to avoid duplicate WidgetID errors.

        Returns
        -------
        bool
            Status of resetting the password.
        """
        if fields is None:
            fields = {'Form name':'Reset password', 'Current password':'Current password',
                      'New password':'New password','Repeat password':'Repeat password',
                      'Reset':'Reset'}
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until a future release
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has
                                   been replaced with the 'fields' parameter. For further
                                   information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticatereset_password""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            reset_password_form = st.form('Reset password', clear_on_submit=clear_on_submit,
                                          key=key)
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password',
                                                  clear_on_submit=clear_on_submit, key=key)
        reset_password_form.subheader('Reset password' if 'Form name' not in fields
                                      else fields['Form name'], key=key)
        username = username.lower()
        password = reset_password_form.text_input('Current password'
                                                  if 'Current password' not in fields
                                                  else fields['Current password'],
                                                  type='password', key=key).strip()
        new_password = reset_password_form.text_input('New password'
                                                      if 'New password' not in fields
                                                      else fields['New password'],
                                                      type='password', key=key).strip()
        new_password_repeat = reset_password_form.text_input('Repeat password'
                                                             if 'Repeat password' not in fields
                                                             else fields['Repeat password'],
                                                             type='password', key=key).strip()
        if reset_password_form.form_submit_button('Reset' if 'Reset' not in fields
                                                  else fields['Reset']):
            if self.authentication_handler.reset_password(username, password, new_password,
                                                          new_password_repeat):
                return True
        return None
    def update_user_details(self, username: str, location: str='main',
                            fields: Optional[Dict[str, str]]=None,
                            clear_on_submit: bool=False, key: Optional[str]=None) -> bool:
        """
        Creates a update user details widget.

        Parameters
        ----------
        username: str
            Username of the user to update user details for.
        location: str
            Location of the update user details widget i.e. main or sidebar.
        fields: dict
            Rendered names of the fields/buttons.
        clear_on_submit: bool
            Clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
        key: str
            Unique key provided to widgets to avoid duplicate WidgetID errors.

        Returns
        -------
        bool
            Status of updating the user details.
        """
        if fields is None:
            fields = {'Form name':'Update user details', 'Field':'Field', 'Name':'Name',
                      'Email':'Email', 'New value':'New value', 'Update':'Update'} 
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until a future release
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter
                                   has been replaced with the 'fields' parameter. For further
                                   information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateupdate_user_details""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            update_user_details_form = st.form('Update user details',
                                               clear_on_submit=clear_on_submit, key=key)
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form('Update user details',
                                                       clear_on_submit=clear_on_submit, key=key)
        update_user_details_form.subheader('Update user details' if 'Form name' not in fields
                                           else fields['Form name'], key=key)
        username = username.lower()
        update_user_details_form_fields = ['Name' if 'Name' not in fields else fields['Name'],
                                           'Email' if 'Email' not in fields else fields['Email']]
        field = update_user_details_form.selectbox('Field' if 'Field' not in fields
                                                   else fields['Field'],
                                                   update_user_details_form_fields, key=key)
        new_value = update_user_details_form.text_input('New value' if 'New value' not in fields
                                                        else fields['New value'],
                                                        key=key).strip()
        if update_user_details_form_fields.index(field) == 0:
            field = 'name'
        elif update_user_details_form_fields.index(field) == 1:
            field = 'email'
        if update_user_details_form.form_submit_button('Update' if 'Update' not in fields
                                                       else fields['Update']):
            if self.authentication_handler.update_user_details(new_value, username, field):
                self.cookie_handler.set_cookie()
                return True
