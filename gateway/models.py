import os, hashlib
from django.db import models
from djorm_pgarray.fields import TextArrayField
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)
from RAPID.tasks import deliver_email


def generate_token():
    return hashlib.md5(os.urandom(32)).hexdigest()


class RegistrationToken(models.Model):

    token = models.CharField(max_length=32, primary_key=True, default=generate_token)
    email = models.EmailField()

    def save(self, *args, **kwargs):
        """ Custom save method to email token upon creation """
        url = "https://www.rapidpivot.com/register"
        subject = "R.A.P.I.D Registration"
        body = '''The following token will allow you to register for the R.A.P.I.D tool: %s.
        Please visit the following URL %s and fill out the necessary information in order to
        complete the registration process. ''' % (str(self.token), url)

        deliver_email.delay(subject=subject, body=body, recipients=[str(self.email)])
        super(RegistrationToken, self).save(*args, **kwargs)


class UserProfileManager(BaseUserManager):

    def create_user(self, email, is_active, password=None):

        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(email=self.normalize_email(email), is_active=is_active)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, is_active, password):

        user = self.create_user(email, is_active, password=password)
        user.is_admin = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class RapidUser(AbstractBaseUser):

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    alerts = models.BooleanField(default=True)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    ip_list = TextArrayField(default=[])
    domain_list = TextArrayField(default=[])

    def get_full_name(self):
        full_name = '%s %s' % (self.last_name.upper(), self.first_name)
        return full_name.strip()

    def get_short_name(self):
        short_name = self.first_name
        return short_name.strip()

    @property
    def is_superuser(self):
        return self.is_admin

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['is_active']

    objects = UserProfileManager()