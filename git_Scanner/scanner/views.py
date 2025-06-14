from django.shortcuts import render
from .forms import ScanForm
from .utils import clone_repo, scan_repository, scan_git_history, generate_report
import shutil

def scan_view(request):
    if request.method == "POST":
        form = ScanForm(request.POST)
        if form.is_valid():
            repo_url = form.cleaned_data["repo_url"]
            try:
                # Clone and scan
                repo_path = clone_repo(repo_url)
                findings = scan_repository(repo_path)
                history_findings = scan_git_history(repo_path)
                report = generate_report(findings, history_findings, repo_url)

                # Store report in session for downloads
                request.session["last_report"] = report

                # Clean up
                shutil.rmtree(repo_path, ignore_errors=True)

                # Render results
                return render(request, "scan_results.html", {"report": report, "repo_url": repo_url})
            except Exception as e:
                form.add_error(None, f"Error: {e}")
    else:
        form = ScanForm()
    return render(request, "scan_form.html", {"form": form})