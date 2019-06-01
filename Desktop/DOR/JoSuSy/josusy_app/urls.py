'''###########################################################################################################
#                                                                                                            #
#   urls.py help us link view function, and view name through which it can be accessed in templates.         #
#   urls.py is used to specify a url through which a webpage could be accessed in an app or a project        #
#   This is an 'josusy_app' application's urls.py page which is included in our main urls.py file.           #
#                                                                                                            #
###########################################################################################################'''
from django.conf.urls import url, include
from josusy_app import views
from django.urls import path, re_path
from django.contrib.auth import views as auth_views
app_name = 'josusy_app'

urlpatterns=[
    #re_path(r'^$',views.index,name='index'),
    #re_path(r'^user_login/$',auth_views.user_login,name='user_login'),
    re_path(r'^user_login/$',views.user_login,name='user_login'),
    re_path(r'^auser_login/$',views.auser_login,name='auser_login'),
    #re_path(r'^register/$',views.register,name='register'),
    re_path(r'^squeue/$',views.squeue,name='squeue'),
]
