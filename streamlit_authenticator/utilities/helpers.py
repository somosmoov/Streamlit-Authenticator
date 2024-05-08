"""
Script description: This module executes the logic for miscellaneous functions for this
library. 

Libraries imported:
- string: Module providing support for ASCII character encoding.
- random: Module generating random characters.
- streamlit: Framework used to build pure Python web applications.
- captcha: Module generating captcha images.
"""

import string
import random
import streamlit as st
from captcha.image import ImageCaptcha

class Helpers:
    """
    This class executes the logic for miscellaneous functions.
    """
    def __init__(self):
        pass
    @classmethod
    def generate_captcha(cls, captcha_name: str) -> tuple:
        """
        Generates a captcha image.

        Parameters
        ----------
        captcha_name: str
            Name of the generated captcha stored in the session state.

        Returns
        -------
        ImageCaptcha
            Randomly generated captcha image.
        """
        image = ImageCaptcha(width=120, height=75)
        if captcha_name not in st.session_state:
            st.session_state[captcha_name] = ''.join(random.choices(string.digits, k=4))
        return image.generate(st.session_state[captcha_name])
    @classmethod
    def generate_random_pw(cls, length: int=16) -> str:
        """
        Generates a random password.

        Parameters
        ----------
        length: int
            Length of the returned password.
            
        Returns
        -------
        str
            Randomly generated password.
        """
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length)).replace(' ','')
