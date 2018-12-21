from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.views.generic.list import ListView
from django.core.urlresolvers import reverse, reverse_lazy
from django.http import Http404

from django_scantron.models import User
from django_scantron.user.forms import UserForm


class UserListView(LoginRequiredMixin, ListView):
    model = User
    template_name = "django_scantron/user_list.html"
    paginate_by = 20
    context_object_name = "user_list"
    allow_empty = True
    page_kwarg = "page"
    paginate_orphans = 0
    fields = [
        "password",
        "last_login",
        "is_superuser",
        "username",
        "first_name",
        "last_name",
        "email",
        "is_staff",
        "is_active",
        "date_joined",
        "groups",
        "user_permissions",
    ]

    def __init__(self, **kwargs):
        return super(UserListView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(UserListView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(UserListView, self).get(request, *args, **kwargs)

    def get_queryset(self):
        return super(UserListView, self).get_queryset()

    def get_allow_empty(self):
        return super(UserListView, self).get_allow_empty()

    def get_context_data(self, *args, **kwargs):
        ret = super(UserListView, self).get_context_data(*args, **kwargs)
        ret["fields"] = self.fields
        return ret

    def get_paginate_by(self, queryset):
        return super(UserListView, self).get_paginate_by(queryset)

    def get_context_object_name(self, object_list):
        return super(UserListView, self).get_context_object_name(object_list)

    def paginate_queryset(self, queryset, page_size):
        return super(UserListView, self).paginate_queryset(queryset, page_size)

    def get_paginator(self, queryset, per_page, orphans=0, allow_empty_first_page=True):
        return super(UserListView, self).get_paginator(queryset, per_page, orphans=0, allow_empty_first_page=True)

    def render_to_response(self, context, **response_kwargs):
        return super(UserListView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(UserListView, self).get_template_names()


class UserDetailView(DetailView):
    model = User
    template_name = "django_scantron/user_detail.html"
    context_object_name = "user"
    slug_field = "slug"
    slug_url_kwarg = "slug"
    pk_url_kwarg = "pk"

    def __init__(self, **kwargs):
        return super(UserDetailView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(UserDetailView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(UserDetailView, self).get(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return super(UserDetailView, self).get_object(queryset)

    def get_queryset(self):
        return super(UserDetailView, self).get_queryset()

    def get_slug_field(self):
        return super(UserDetailView, self).get_slug_field()

    def get_context_data(self, **kwargs):
        ret = super(UserDetailView, self).get_context_data(**kwargs)
        return ret

    def get_context_object_name(self, obj):
        return super(UserDetailView, self).get_context_object_name(obj)

    def render_to_response(self, context, **response_kwargs):
        return super(UserDetailView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(UserDetailView, self).get_template_names()


class UserCreateView(CreateView):
    model = User
    form_class = UserForm
    fields = [
        "password",
        "last_login",
        "is_superuser",
        "username",
        "first_name",
        "last_name",
        "email",
        "is_staff",
        "is_active",
        "date_joined",
        "groups",
        "user_permissions",
    ]
    template_name = "django_scantron/user_create.html"
    success_url = reverse_lazy("user_list")

    def __init__(self, **kwargs):
        return super(UserCreateView, self).__init__(**kwargs)

    def dispatch(self, request, *args, **kwargs):
        return super(UserCreateView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(UserCreateView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super(UserCreateView, self).post(request, *args, **kwargs)

    def get_form_class(self):
        return super(UserCreateView, self).get_form_class()

    def get_form(self, form_class=UserForm):
        return super(UserCreateView, self).get_form(form_class)

    def get_form_kwargs(self, **kwargs):
        return super(UserCreateView, self).get_form_kwargs(**kwargs)

    def get_initial(self):
        return super(UserCreateView, self).get_initial()

    def form_invalid(self, form):
        return super(UserCreateView, self).form_invalid(form)

    def form_valid(self, form):
        obj = form.save(commit=False)
        obj.save()
        return super(UserCreateView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(UserCreateView, self).get_context_data(**kwargs)
        return ret

    def render_to_response(self, context, **response_kwargs):
        return super(UserCreateView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(UserCreateView, self).get_template_names()

    def get_success_url(self):
        return self.success_url


class UserUpdateView(UpdateView):
    model = User
    form_class = UserForm
    fields = [
        "password",
        "last_login",
        "is_superuser",
        "username",
        "first_name",
        "last_name",
        "email",
        "is_staff",
        "is_active",
        "date_joined",
        "groups",
        "user_permissions",
    ]
    template_name = "django_scantron/user_update.html"
    initial = {}
    slug_field = "slug"
    slug_url_kwarg = "slug"
    pk_url_kwarg = "pk"
    context_object_name = "user"

    def __init__(self, **kwargs):
        return super(UserUpdateView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(UserUpdateView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        return super(UserUpdateView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super(UserUpdateView, self).post(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return super(UserUpdateView, self).get_object(queryset)

    def get_queryset(self):
        return super(UserUpdateView, self).get_queryset()

    def get_slug_field(self):
        return super(UserUpdateView, self).get_slug_field()

    def get_form_class(self):
        return super(UserUpdateView, self).get_form_class()

    def get_form(self, form_class=UserForm):
        return super(UserUpdateView, self).get_form(form_class)

    def get_form_kwargs(self, **kwargs):
        return super(UserUpdateView, self).get_form_kwargs(**kwargs)

    def get_initial(self):
        return super(UserUpdateView, self).get_initial()

    def form_invalid(self, form):
        return super(UserUpdateView, self).form_invalid(form)

    def form_valid(self, form):
        obj = form.save(commit=False)
        obj.save()
        return super(UserUpdateView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        ret = super(UserUpdateView, self).get_context_data(**kwargs)
        return ret

    def get_context_object_name(self, obj):
        return super(UserUpdateView, self).get_context_object_name(obj)

    def render_to_response(self, context, **response_kwargs):
        return super(UserUpdateView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(UserUpdateView, self).get_template_names()

    def get_success_url(self):
        return reverse("user_list")


class UserDeleteView(DeleteView):
    model = User
    template_name = "django_scantron/user_delete.html"
    slug_field = "slug"
    slug_url_kwarg = "slug"
    pk_url_kwarg = "pk"
    context_object_name = "user"

    def __init__(self, **kwargs):
        return super(UserDeleteView, self).__init__(**kwargs)

    def dispatch(self, *args, **kwargs):
        return super(UserDeleteView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        raise Http404

    def post(self, request, *args, **kwargs):
        return super(UserDeleteView, self).post(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return super(UserDeleteView, self).delete(request, *args, **kwargs)

    def get_object(self, queryset=None):
        return super(UserDeleteView, self).get_object(queryset)

    def get_queryset(self):
        return super(UserDeleteView, self).get_queryset()

    def get_slug_field(self):
        return super(UserDeleteView, self).get_slug_field()

    def get_context_data(self, **kwargs):
        ret = super(UserDeleteView, self).get_context_data(**kwargs)
        return ret

    def get_context_object_name(self, obj):
        return super(UserDeleteView, self).get_context_object_name(obj)

    def render_to_response(self, context, **response_kwargs):
        return super(UserDeleteView, self).render_to_response(context, **response_kwargs)

    def get_template_names(self):
        return super(UserDeleteView, self).get_template_names()

    def get_success_url(self):
        return reverse("user_list")
