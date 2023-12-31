from flask_wtf import FlaskForm
from wtforms import Form, validators, StringField, PasswordField, EmailField, ValidationError, TelField


#Custom Validators
#==========================================================================================

    
def VerifyPassword(form, field):
    password = form.password.data
    re_password = field.data

    if password != re_password:
        raise ValidationError('The passwords you entered do not match')


#Forms
#==========================================================================================
class RegistrationForm(Form):
    email = EmailField('Email', [validators.Email(),validators.length(max=320), validators.DataRequired()])
    username = StringField('Username', [validators.length(min=8, max=20), validators.DataRequired()])
    password = PasswordField('Password', [validators.length(min=8, max=254), validators.DataRequired()])
    re_password = PasswordField('Re-Enter Password', [VerifyPassword, validators.length(min=8, max=254), validators.DataRequired()])

class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

class OTPForm(Form):
    otp = StringField('OTP', [validators.DataRequired(), validators.length(max=6)])

class UserDataForm(Form):
    name = StringField('Name', [validators.length(max=50)])
    phone = TelField('Phone')
    address = StringField('Address', [validators.length(max=100)])