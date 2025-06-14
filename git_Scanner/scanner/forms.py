from django import forms

class ScanForm(forms.Form):
    repo_url = forms.URLField(
        label="Repository URL",
        max_length=500,
        widget=forms.URLInput(attrs={"class": "form-control", "placeholder": "https://github.com/user/repo.git"})
    )