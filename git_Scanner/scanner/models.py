from django.db import models

class ScanResult(models.Model):
    repo_url = models.URLField(max_length=500)
    scan_time = models.DateTimeField(auto_now_add=True)
    report = models.JSONField()  # Store the full report as JSON
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.repo_url} - {self.scan_time}"