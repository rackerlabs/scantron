from django import forms
from django_scantron.models import User


class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "username", "email", "is_active", "is_superuser"]
        exclude = []
        widgets = None
        localized_fields = None
        labels = {}
        help_texts = {}
        error_messages = {}

    def __init__(self, *args, **kwargs):
        return super(UserForm, self).__init__(*args, **kwargs)

    def is_valid(self):
        return super(UserForm, self).is_valid()

    def full_clean(self):
        return super(UserForm, self).full_clean()

    def clean_password(self):
        password = self.cleaned_data.get("password", None)
        return password

    def clean_last_login(self):
        last_login = self.cleaned_data.get("last_login", None)
        return last_login

    def clean_is_superuser(self):
        is_superuser = self.cleaned_data.get("is_superuser", None)
        return is_superuser

    def clean_username(self):
        username = self.cleaned_data.get("username", None).lower()
        return username

    def clean_first_name(self):
        first_name = self.cleaned_data.get("first_name", None)
        return first_name

    def clean_last_name(self):
        last_name = self.cleaned_data.get("last_name", None)
        return last_name

    def clean_email(self):
        email = self.cleaned_data.get("email", None)
        return email

    def clean_is_staff(self):
        is_staff = self.cleaned_data.get("is_staff", None)
        return is_staff

    def clean_is_active(self):
        is_active = self.cleaned_data.get("is_active", None)
        return is_active

    def clean_date_joined(self):
        date_joined = self.cleaned_data.get("date_joined", None)
        return date_joined

    def clean_groups(self):
        groups = self.cleaned_data.get("groups", None)
        return groups

    def clean_user_permissions(self):
        user_permissions = self.cleaned_data.get("user_permissions", None)
        return user_permissions

    def clean(self):
        return super(UserForm, self).clean()

    def validate_unique(self):
        return super(UserForm, self).validate_unique()

    def save(self, commit=True):
        return super(UserForm, self).save(commit)
