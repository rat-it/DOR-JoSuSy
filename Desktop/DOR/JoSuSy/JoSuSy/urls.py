'''###########################################################################################################
#                                                                                                            #
#   urls.py help us link view function, and view name which can be used to access in templates.              #
#   urls.py is used to specify a url through which a webpage could be accessed in an app or a project        #
#   This is our main project's urls.py page.                                                                 #
#                                                                                                            #
###########################################################################################################'''
"""JoSuSy URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path, include
from django.conf.urls import url
from josusy_app import views

from django.views.generic.base import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^alogout/',views.ALogout,name='Alogout'),
    re_path(r'^alogv/',views.AdminLogV,name='Alogv'),
    re_path(r'^aaddm/',views.AdminAddM,name='Aaddm'),
    re_path(r'^adelm/$',views.AdmnDelM,name='DUF'),
    re_path(r'^josusy_app/',include('josusy_app.urls')),
    re_path(r'^logout/$',views.user_logout,name='logout'),
    re_path(r'^changepassword/$',views.ChangePassword,name='changepassword'),
    re_path(r'^special/',views.special,name='special'),
    re_path(r'^$',views.index,name='index'),
    re_path(r'^jobsubmissiontype/',views.JobSubmissionType,name='SelectSubmissionType'),
    re_path(r'^ahome/',views.AHome,name='SelectTask'),
    re_path(r'^jobsubmission/',views.JobDataV,name='JobData'),
    re_path(r'^jobsubmissions/',views.JobDataS,name='JobDataS'),
    re_path(r'^ssl/',views.SSL,name='SSLF'),
    re_path(r'^ssc/',views.SSC,name='SSLF'),
    re_path(r'^pml/',views.PML,name='PMLF'),
    re_path(r'^pmc/',views.PMC,name='PMLF'),
    re_path(r'^psl/',views.PSL,name='PSLF'),
    re_path(r'^psc/',views.PSC,name='PSLF'),
    re_path(r'^readscript/',views.ReadScript,name='readscript'),
    re_path(r'^show/',views.display,name='display'),
    re_path(r'^user_files/',views.user_files,name='user_files'),
]
