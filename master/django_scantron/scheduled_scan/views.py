from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.list import ListView

from django_scantron.models import ScheduledScan


class ScheduledScanListView(LoginRequiredMixin, ListView):
    login_url = "/login/"
    model = ScheduledScan
    template_name = "django_scantron/scheduled_scan_list.html"
    # paginate_by = 20
    context_object_name = "scheduled_scan_list"
    allow_empty = True
    page_kwarg = "page"
    paginate_orphans = 0

    def __init__(self, **kwargs):
        return super(ScheduledScanListView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(ScheduledScanListView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(ScheduledScanListView, self).get(request, *args, **kwargs)

    def get_queryset(self):
        return super(ScheduledScanListView, self).get_queryset()

    def get_allow_empty(self):
        return super(ScheduledScanListView, self).get_allow_empty()

    def get_context_data(self, *args, **kwargs):
        ret = super(ScheduledScanListView, self).get_context_data(*args, **kwargs)
        return ret

    def get_paginate_by(self, queryset):
        return super(ScheduledScanListView, self).get_paginate_by(queryset)

    def get_context_object_name(self, object_list):
        return super(ScheduledScanListView, self).get_context_object_name(object_list)

    def paginate_queryset(self, queryset, page_size):
        return super(ScheduledScanListView, self).paginate_queryset(queryset, page_size)

    def get_paginator(self, queryset, per_page, orphans=0, allow_empty_first_page=True):
        return super(ScheduledScanListView, self).get_paginator(
            queryset, per_page, orphans=0, allow_empty_first_page=True
        )

    def render_to_response(self, context, **response_kwargs):
        return super(ScheduledScanListView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(ScheduledScanListView, self).get_template_names()
