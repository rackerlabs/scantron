from django.contrib.auth import views as auth_views
from django.conf.urls import url

urlpatterns = [
    url(r'^logout/', auth_views.logout, {'next_page': '/login'}, name='logout'),
]
