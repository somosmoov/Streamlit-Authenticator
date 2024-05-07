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
    def generate_captcha(cls) -> tuple:
        """
        Generates a captcha image.

        Returns
        -------
        int
            The randomly generated four digit captcha.
        ImageCaptcha
            The randomly generated captcha object.
        """
        image = ImageCaptcha(width=120, height=75)
        if 'generated_captcha' not in st.session_state:
            st.session_state['generated_captcha'] = ''.join(random.choices(string.digits, k=4))
        return image.generate(st.session_state['generated_captcha'])
    @classmethod
    def generate_random_pw(cls, length: int=16) -> str:
        """
        Generates a random password.

        Parameters
        ----------
        length: int
            The length of the returned password.
        Returns
        -------
        str
            The randomly generated password.
        """
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length)).replace(' ','')
