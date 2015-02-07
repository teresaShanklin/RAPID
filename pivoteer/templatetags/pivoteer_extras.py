from django import template
from RAPID.checks import IndicatorCheck

register = template.Library()

@register.filter(name='verify_type')
def verify_type(value, validator):

    check = IndicatorCheck(value)

    if validator == "ip":
        return check.valid_ip()

    elif validator == "domain":
        return check.valid_domain()

    elif validator == "email":
        return check.valid_email()

    else:
        return False