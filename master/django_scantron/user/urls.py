from django.conf.urls import url

# fmt:off
from django_scantron.user.views import (
    UserListView,
    UserCreateView,
    UserDetailView,
    UserUpdateView,
    UserDeleteView
)
# fmt:on

urlpatterns = [
    url(r"^user/create/$", UserCreateView.as_view(), name="user_create"),
    url(r"^user/(?P<pk>\d+)/update/$", UserUpdateView.as_view(), name="user_update"),
    url(r"^user/(?P<pk>\d+)/delete/$", UserDeleteView.as_view(), name="user_delete"),
    url(r"^user/(?P<pk>\d+)/$", UserDetailView.as_view(), name="user_detail"),
    url(r"^user/$", UserListView.as_view(), name="user_list"),
]
