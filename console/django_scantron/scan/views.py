from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import Http404
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views.generic.list import ListView

from django_scantron.models import Scan
from django_scantron.scan.forms import ScanForm


class ScanListView(LoginRequiredMixin, ListView):
    login_url = "/login/"
    model = Scan
    template_name = "django_scantron/scan_list.html"
    # paginate_by = 20
    context_object_name = "scan_list"
    allow_empty = True
    page_kwarg = "page"
    paginate_orphans = 0

    def __init__(self, **kwargs):
        return super(ScanListView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(ScanListView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(ScanListView, self).get(request, *args, **kwargs)

    def get_queryset(self):
        return super(ScanListView, self).get_queryset()

    def get_allow_empty(self):
        return super(ScanListView, self).get_allow_empty()

    def get_context_data(self, *args, **kwargs):
        ret = super(ScanListView, self).get_context_data(*args, **kwargs)
        return ret

    def get_paginate_by(self, queryset):
        return super(ScanListView, self).get_paginate_by(queryset)

    def get_context_object_name(self, object_list):
        return super(ScanListView, self).get_context_object_name(object_list)

    def paginate_queryset(self, queryset, page_size):
        return super(ScanListView, self).paginate_queryset(queryset, page_size)

    def get_paginator(self, queryset, per_page, orphans=0, allow_empty_first_page=True):
        return super(ScanListView, self).get_paginator(queryset, per_page, orphans=0, allow_empty_first_page=True)

    def render_to_response(self, context, **response_kwargs):
        return super(ScanListView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(ScanListView, self).get_template_names()


class ScanDetailView(LoginRequiredMixin, DetailView):
    login_url = "/login/"
    model = Scan
    template_name = "django_scantron/scan_detail.html"
    context_object_name = "scan"
    slug_field = "slug"
    slug_url_kwarg = "slug"
    pk_url_kwarg = "pk"

    def __init__(self, **kwargs):
        return super(ScanDetailView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(ScanDetailView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(ScanDetailView, self).get(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return super(ScanDetailView, self).get_object(queryset)

    def get_queryset(self):
        return super(ScanDetailView, self).get_queryset()

    def get_slug_field(self):
        return super(ScanDetailView, self).get_slug_field()

    def get_context_data(self, **kwargs):
        ret = super(ScanDetailView, self).get_context_data(**kwargs)
        return ret

    def get_context_object_name(self, obj):
        return super(ScanDetailView, self).get_context_object_name(obj)

    def render_to_response(self, context, **response_kwargs):
        return super(ScanDetailView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(ScanDetailView, self).get_template_names()


class ScanCreateView(LoginRequiredMixin, CreateView):
    login_url = "/login/"
    model = Scan
    form_class = ScanForm
    fields = ["site_name", "scan_command", "scan_type", "target_file", "scan_engine", "start_time"]
    template_name = "django_scantron/scan_create.html"
    success_url = reverse_lazy("scan_list")

    def __init__(self, **kwargs):
        return super(ScanCreateView, self).__init__(**kwargs)

    def dispatch(self, request, *args, **kwargs):
        return super(ScanCreateView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(ScanCreateView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super(ScanCreateView, self).post(request, *args, **kwargs)

    def get_form_class(self):
        return super(ScanCreateView, self).get_form_class()

    def get_form(self, form_class=ScanForm):
        return super(ScanCreateView, self).get_form(form_class)

    def get_form_kwargs(self, **kwargs):
        return super(ScanCreateView, self).get_form_kwargs(**kwargs)

    def get_initial(self):
        return super(ScanCreateView, self).get_initial()

    def form_invalid(self, form):
        return super(ScanCreateView, self).form_invalid(form)

    def form_valid(self, form):
        obj = form.save(commit=False)
        obj.save()
        return super(ScanCreateView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(ScanCreateView, self).get_context_data(**kwargs)
        return ret

    def render_to_response(self, context, **response_kwargs):
        return super(ScanCreateView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(ScanCreateView, self).get_template_names()

    def get_success_url(self):
        return self.success_url


class ScanUpdateView(LoginRequiredMixin, UpdateView):
    login_url = "/login/"
    model = Scan
    form_class = ScanForm
    fields = ["site_name", "scan_command", "scan_type", "target_file", "scan_engine", "start_time"]
    template_name = "django_scantron/scan_update.html"
    initial = {}
    slug_field = "slug"
    slug_url_kwarg = "slug"
    pk_url_kwarg = "pk"
    context_object_name = "scan"

    def __init__(self, **kwargs):
        return super(ScanUpdateView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(ScanUpdateView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(ScanUpdateView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super(ScanUpdateView, self).post(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return super(ScanUpdateView, self).get_object(queryset)

    def get_queryset(self):
        return super(ScanUpdateView, self).get_queryset()

    def get_slug_field(self):
        return super(ScanUpdateView, self).get_slug_field()

    def get_form_class(self):
        return super(ScanUpdateView, self).get_form_class()

    def get_form(self, form_class=ScanForm):
        return super(ScanUpdateView, self).get_form(form_class)

    def get_form_kwargs(self, **kwargs):
        return super(ScanUpdateView, self).get_form_kwargs(**kwargs)

    def get_initial(self):
        return super(ScanUpdateView, self).get_initial()

    def form_invalid(self, form):
        return super(ScanUpdateView, self).form_invalid(form)

    def form_valid(self, form):
        obj = form.save(commit=False)
        obj.save()
        return super(ScanUpdateView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(ScanUpdateView, self).get_context_data(**kwargs)
        return ret

    def get_context_object_name(self, obj):
        return super(ScanUpdateView, self).get_context_object_name(obj)

    def render_to_response(self, context, **response_kwargs):
        return super(ScanUpdateView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(ScanUpdateView, self).get_template_names()

    def get_success_url(self):
        return reverse("scan_list")


class ScanDeleteView(LoginRequiredMixin, DeleteView):
    login_url = "/login/"
    model = Scan
    template_name = "django_scantron/scan_delete.html"
    slug_field = "slug"
    slug_url_kwarg = "slug"
    pk_url_kwarg = "pk"
    context_object_name = "scan"

    def __init__(self, **kwargs):
        return super(ScanDeleteView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(ScanDeleteView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        raise Http404

    def post(self, request, *args, **kwargs):
        return super(ScanDeleteView, self).post(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return super(ScanDeleteView, self).delete(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return super(ScanDeleteView, self).get_object(queryset)

    def get_queryset(self):
        return super(ScanDeleteView, self).get_queryset()

    def get_slug_field(self):
        return super(ScanDeleteView, self).get_slug_field()

    def get_context_data(self, **kwargs):
        ret = super(ScanDeleteView, self).get_context_data(**kwargs)
        return ret

    def get_context_object_name(self, obj):
        return super(ScanDeleteView, self).get_context_object_name(obj)

    def render_to_response(self, context, **response_kwargs):
        return super(ScanDeleteView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(ScanDeleteView, self).get_template_names()

    def get_success_url(self):
        return reverse("scan_list")
