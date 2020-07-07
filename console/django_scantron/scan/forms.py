from django import forms
from django_scantron.models import Scan


class ScanForm(forms.ModelForm):
    class Meta:
        model = Scan
        fields = ["site", "scan_name", "start_time", "recurrences"]
        exclude = []
        widgets = None
        localized_fields = None
        labels = {}
        help_texts = {}
        error_messages = {}

    def __init__(self, *args, **kwargs):
        return super(ScanForm, self).__init__(*args, **kwargs)

    def is_valid(self):
        return super(ScanForm, self).is_valid()

    def full_clean(self):
        return super(ScanForm, self).full_clean()

    def clean_site(self):
        site_name = self.cleaned_data.get("site", None)
        return site_name

    def clean_scan_name(self):
        scan_name = self.cleaned_data.get("scan_name", None)
        return scan_name

    def clean_start_time(self):
        start_time = self.cleaned_data.get("start_time", None)
        return start_time

    def clean(self):
        return super(ScanForm, self).clean()

    def validate_unique(self):
        return super(ScanForm, self).validate_unique()

    def save(self, commit=True):
        return super(ScanForm, self).save(commit)
