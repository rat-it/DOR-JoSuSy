'''################################################################
#                                                                 #
#   forms.py help us create new forms to load in templates.       #
#   Code reusability increases and organisation gets easy.        #
#                                                                 #
################################################################'''
from django import forms
from django.contrib.auth.models import User
from josusy_app.models import Logger
from josusy_app.models import Admins
#from josusy_app.models import UserProfileInfo
from django.core import validators
from django.core.validators import RegexValidator

class UserForm(forms.ModelForm):
    user = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta():
        model = Logger
        fields = ('user','password')

class DUF(forms.ModelForm):
    user = forms.CharField()

    class Meta():
        model = Logger
        fields = ('user',)

class ChangePasskey(forms.Form):
    password = forms.CharField(label='New Password:', widget=forms.PasswordInput(attrs={'placeholder': 'New strong password'}))
    repassword = forms.CharField(label='Re-Enter Password:', widget=forms.PasswordInput(attrs={'placeholder': 'Same password above'}))

class AUserForm(forms.ModelForm):
    name = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta():
        model = Admins
        fields = ('name','password')

ATASKS={
    ('addmember','Add members to cluster'),
    ('delmember','Delete members from cluster'),
    ('logview','View System Log'),
}

class AdF(forms.Form):
    Desire = forms.CharField(widget=forms.Select(choices=ATASKS))

'''class AloginF(forms.ModelForm):
    name = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta():
        model = Admins
        fields = ('name','password')'''

QUEUE={
    ('shortq','Shortq'),
    ('longq','Longq'),
    ('gpuq','Gpuq'),
    ('workq','Workq'),
    ('debugq','Debugq')
}

class JobData(forms.Form):
    Job_Name = forms.CharField(max_length=30, required=True, validators=[ RegexValidator( regex='^[a-zA-Z0-9_]*$', message='Please enter a proper aplhanumeric job name!', code='invalid_username'),])
    #Queue = forms.CharField(widget=forms.Select(choices=QUEUE))
    Number_of_Nodes = forms.IntegerField(label='No. of nodes:', required=True, validators=[validators.MaxValueValidator(3)])
    No_of_cores_per_node = forms.IntegerField(label='No. of cores per node:', required=True, validators=[validators.MaxValueValidator(4)])
    #Walltime = forms.IntegerField(label='Walltime(in hours):', validators=[validators.MinValueValidator(0)])

class SSLF(forms.Form):
    Job_Name = forms.CharField(max_length=30, required=True, validators=[ RegexValidator( regex='^[a-zA-Z0-9_]*$', message='Please enter a proper aplhanumeric job name!', code='invalid_username'),])
    #Queue = forms.CharField(widget=forms.Select(choices=QUEUE))
    Number_of_Nodes = forms.IntegerField(label='No. of nodes:', required=True, validators=[validators.MaxValueValidator(3)])
    #No_of_cores_per_node = forms.IntegerField(validators=[validators.MaxValueValidator(4)])
    #Walltime = forms.IntegerField(label='Walltime(in hours):', validators=[validators.MinValueValidator(0)])

class PMLF(forms.Form):
    Job_Name = forms.CharField(max_length=30, required=True, validators=[ RegexValidator( regex='^[a-zA-Z0-9_]*$', message='Please enter a proper aplhanumeric job name!', code='invalid_username'),])
    Queue = forms.CharField(widget=forms.Select(choices=QUEUE))
    Number_of_Nodes = forms.IntegerField(label='No. of nodes:', required=True, validators=[validators.MaxValueValidator(27)])
    No_of_cores_per_node = forms.IntegerField(label='No. of cores per node:', required=True, validators=[validators.MaxValueValidator(28)])
    #Walltime = forms.IntegerField(label='Walltime(in hours):', validators=[validators.MinValueValidator(0)])

class PSLF(forms.Form):
    Job_Name = forms.CharField(max_length=30, required=True, validators=[ RegexValidator( regex='^[a-zA-Z0-9_]*$', message='Please enter a proper aplhanumeric job name!', code='invalid_username'),])
    #Queue = forms.CharField(widget=forms.Select(choices=QUEUE))
    Number_of_Nodes = forms.IntegerField(label='Number of Nodes:', required=True, validators=[validators.MaxValueValidator(27)])
    #No_of_cores_per_node = forms.IntegerField(validators=[validators.MaxValueValidator(4)])
    #Walltime = forms.IntegerField(label='Walltime(in hours):', validators=[validators.MinValueValidator(0)])

class JobDataS(forms.Form):
    Job_Name = forms.CharField(max_length=30, required=True, validators=[ RegexValidator( regex='^[a-zA-Z0-9_]*$', message='Please enter a proper aplhanumeric job name!', code='invalid_username'),])
    #Queue = forms.CharField(widget=forms.Select(choices=QUEUE))
    Number_of_Nodes = forms.IntegerField(label='No. of nodes:', required=True, validators=[validators.MaxValueValidator(3)])
    No_of_cores_per_node = forms.IntegerField(label='No. of cores per node:', required=True, validators=[validators.MaxValueValidator(4)])
    #Walltime = forms.IntegerField(label='Walltime(in hours):', validators=[validators.MinValueValidator(0)])

SCHEDULER={
    ('slurm','SLURM'),
    ('pbs','PBS'),
}
RUNTYPE={
    ('sequential','SERIAL'),
    ('mpi','MPI'),
    #('mpitch','MPITCH'),
    #('srun','SRUN'),
}
FILELOCATION={
    ('local','Local Device'),
    ('cluster','Cluster'),
}
class SelectSubmissionType(forms.Form):
    Scheduler = forms.CharField(widget=forms.Select(choices=SCHEDULER))
    How_to_execute = forms.CharField(widget=forms.Select(choices=RUNTYPE))
    Location_of_file = forms.CharField(widget=forms.Select(choices=FILELOCATION))
