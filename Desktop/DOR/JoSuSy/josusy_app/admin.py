'''##############################################################################################################
#                                                                                                               #
#   admin.py help us access database with a better UI, if linked with models.                                   #
#   admin.py has many more functionality then just data view, creation of admin pannel is also possible.        #
#                                                                                                               #
##############################################################################################################'''
from django.contrib import admin
from josusy_app.models import Logger
from josusy_app.models import Admins

# Register your models here.
admin.site.register(Logger)
admin.site.register(Admins)
