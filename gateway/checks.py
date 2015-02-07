"""
Application verification checks
"""
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from gateway.models import RegistrationToken
User = get_user_model()


class PasswordChecks():

    def __init__(self):

        self.min_length = 8
        self.max_length = 32
        self.requirements = "Password must be between 8 and 32 characters long"

    def password_format(self, password):
        """ Verify passwords meet complexity requirements """

        if self.min_length < len(password) < self.max_length:
            return True
        else:
            return False

    def passwords_match(self, password, verification_password):
        """ Verify passwords match """

        if password == verification_password:
            return True
        else:
            return False


class UserChecks():

    def __init__(self):
        pass

    def email_exists(self, email):
        """ Check if email already exists """

        try:
            User.objects.get(email__exact=email)
        except ObjectDoesNotExist:
            return False
        else:
            return True


class OtherChecks():

    def __init__(self):
        pass

    def token_exists(self, token):
        """ Check for a valid token to allow for registration """

        try:
            RegistrationToken.objects.get(token__exact=token)
        except ObjectDoesNotExist:
            return False
        else:
            return True