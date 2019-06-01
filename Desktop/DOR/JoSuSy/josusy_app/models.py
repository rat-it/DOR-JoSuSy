'''########################################################################################
#                                                                                         #
#   models.py help us create new models(database tables/relations) for our project.       #
#   Changing database schemas and maipulating columns and relation gets easy.             #
#                                                                                         #
########################################################################################'''
from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Logger(models.Model):
    user = models.CharField(max_length=100)
    password = models.CharField(max_length=129)
    lastlogin = models.DateTimeField()


    def __str__(self):
        return self.user

class Admins(models.Model):
    name = models.CharField(max_length=100)
    password = models.CharField(max_length=129)

    def __str__(self):
        return self.name

"""class UserProfileInfo(models.Model):
    user =  models.OneToOneField(User)


    def __str__(self):
        return self.user.username
"""
