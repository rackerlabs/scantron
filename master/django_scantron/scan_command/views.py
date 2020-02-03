from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.list import ListView
from django.views.generic.edit import CreateView, DeleteView, UpdateView

from django_scantron.models import ScanCommand


class ScanCommandListView(LoginRequiredMixin, ListView):
    login_url = "/login/"
    model = ScanCommand
    template_name = "django_scantron/scan_command_list.html"
    context_object_name = "scan_command_list"


class ScanCommandCreateView(LoginRequiredMixin, CreateView):
    login_url = "/login/"
    model = ScanCommand
    template_name = "django_scantron/scan_command_create.html"
    context_object_name = "scan_command_create"
    fields = ["id", "scan_binary", "scan_command_name", "scan_command"]


# class ScanCommandDeleteView(LoginRequiredMixin, DeleteView):
#     login_url = "/login/"
#     model = ScanCommand
#     template_name = "django_scantron/scan_command_create.html"
#     context_object_name = "scan_command_create"
#     fields = ["id", "scan_binary", "scan_command_name", "scan_command"]


class ScanCommandUpdateView(LoginRequiredMixin, UpdateView):
    login_url = "/login/"
    model = ScanCommand
    fields = ["id", "scan_binary", "scan_command_name", "scan_command"]
    template_name_suffix = "_update"
