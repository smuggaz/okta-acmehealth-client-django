from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^login', views.login_controller, name='login_controller'),
    url(r'^callback', views.callback_controller, name='callback_controller'),
    url(r'^$', views.home_controller, name='home_controller'),
    url(r'^logout/', views.logout_controller, name='logout_controller'),
]