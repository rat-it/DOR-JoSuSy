'''#################################################################################################
#                                                                                                  #
#   A view is a place where we put the "logic" of our application.                                 #
#   It will request information from the model/form you created before and pass it to a template.  #
#   Views are just Python functions.                                                                #
#                                                                                                  #
#################################################################################################'''
#importing libraries
from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from josusy_app.forms import UserForm
from josusy_app.forms import DUF
from django.contrib.auth.hashers import make_password
from josusy_app import forms
from josusy_app.models import Logger
from josusy_app.models import Admins
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate,login,logout
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response
from django.core.files.storage import FileSystemStorage
from django.conf import settings

import datetime
import logging
import os
import hashlib
import itertools
import subprocess
# Create your views here.

#Object initialised to generate Logs
logger = logging.getLogger(__name__)

#Admin logout view function
def ALogout(request):
    ip = get_client_ip(request)
    logger.info(request.session['admn']+' logged out from '+ip+' at ')
    del request.session['admn']
    return HttpResponseRedirect(reverse('index'))

#Adding NEW USERS to cluster by admin
def AdminAddM(request):
    try:
        #Admin session check
        usr = request.session['admn']
        if bool(usr) :
            if request.method == "POST":
                user_form = DUF(data=request.POST)
                if user_form.is_valid():
                    un = user_form.data['user']
                    name = user_form.data['user']
                    if bool(Logger.objects.filter(user=name).exists()):
                        #Check for any existing user
                        return HttpResponse('<script>alert("User with such credentials already exist! \n Please enter another username! "); window.location.href="http://10.20.4.65:8000/ahome/";</script>')
                    else:
                        phd = 'ipr_'+un
                        paswd = hashlib.sha512(phd.encode())
                        password = paswd.hexdigest()
                        lt = datetime.datetime.now()
                        l1 = Logger(user=un,password=password,lastlogin=lt)
                        l1.save()
                        #script for creating user on cluster
                        os.system("bash /kuberadir/share/adduser_pi.sh "+un+" 3")
                        ip = get_client_ip(request)
                        logger.info(user_form.data['user']+" was added to cluster by "+request.session['admn']+" from "+ip+" at ")
                        return HttpResponse('<script>alert("User created succesfully!"); window.location.href="http://10.20.4.65:8000/";</script>')
                else:
                    print(user_form.errors)
            else:
                user_form = DUF()
            return render(request, 'josusy_app/adminaddm.html',{'user_form':user_form})
        else:
            ip = get_client_ip(request)
            logger.critical('Attempt of registering a user without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login!"); window.location.href="http://10.20.4.65:8000/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#Deleting EXISTING USERS from cluster by admin
def AdmnDelM(request):
    try:
        usr = request.session['admn']
        if bool(usr) :
            if request.method == "POST":
                user_form = DUF(data = request.POST)
                if user_form.is_valid():
                    un = user_form.data['user']
                    #Script for deleting user from cluster
                    os.system("bash /kuberadir/share/deleteuser.sh "+un+" 3")
                    Logger.objects.filter(user=un).delete()
                    ip = get_client_ip(request)
                    logger.info(user_form.data['user']+" was removed from cluster by "+request.session['admn']+" from "+ip+" at ")
                    return HttpResponse('<script>alert("User removed succesfully!"); window.location.href="http://10.20.4.65:8000/";</script>')
                else:
                    print(user_form.errors)
            else:
                user_form = DUF()
            return render(request, 'josusy_app/admindelm.html',{'user_form':user_form})
        else:
            ip = get_client_ip(request)
            logger.critical('Attempt of removing a user without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login!"); window.location.href="http://10.20.4.65:8000/";</script>')
    except Exception as ex:
        return HttpResponse('<script>alert("exceptr!");</script>')
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#Retrieving Client IP Address
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

#Home Page view function
def index(request):
    #Command that provides node status of the cluster
    os.system("scontrol -o show nodes | awk '{print $11,$4,$16,$17}' > m.txt")
    f = open("m.txt","r")
    a1 = []
    for line in f:
    	fields=line.split(" ")
    	f1 = fields[0]
    	f2 = fields[1]
    	f3 = fields[2]
    	f4 = fields[3]

    	g1 = f1.split("=")
    	g11 = g1[1]
    	h1 = g11.split(".")
    	h11 = h1[3]

    	g2 = f2.split("=")
    	g21 = g2[1]

    	g3 = f3.split("=")
    	g31 = g3[1]

    	g4 = f4.split("=")
    	g41 = g4[1]

    	if g41.split("\n"):
    		j1 = g41.split("\n")
    		j11 = j1[0]
    	else:
    		j11 = g41

    	a1.append(h11)
    	a1.append(g21)
    	a1.append(g31)
    	a1.append(j11)

    #Command to fetch master ustilization through 'top' command
    os.system("sshpass -p 'rootpassword' ssh -t pi@pi-master 'top -b -n 2 | grep '%Cpu' ' > piuti.txt")
    with open("piuti.txt") as p:
        for line in itertools.islice(p, 1, 2):
            uti1 = line.split("  ")
            uti11 = uti1[1]
            uti12 = uti11.split(" ")
            uti13 = uti12[0]
            a1.append(uti13)
    #TOdO:fetch node names from master using any slurm command and fetch their temperature
    #Fetch temperature of nodes
    os.system("sshpass -p 'rootpassword' ssh -t pi@pi-master 'vcgencmd measure_temp' > t00.txt")
    os.system("sshpass -p 'rootpassword' ssh -t pi@pi01 'vcgencmd measure_temp' > t01.txt")
    os.system("sshpass -p 'rootpassword' ssh -t pi@pi02 'vcgencmd measure_temp' > t02.txt")
    os.system("sshpass -p 'rootpassword' ssh -t pi@pi03 'vcgencmd measure_temp' > t03.txt")
    tm = open("t00.txt","r")
    #Not optimised yet
    for lin in tm:
        temp = lin.split("=")
        t1 = temp[1]
        t11 = t1.split(".")
        t2 = t11[0]
        a1.append(t2)
    tm.close()
    tm = open("t01.txt","r")
    for lin in tm:
        temp = lin.split("=")
        t1 = temp[1]
        t11 = t1.split(".")
        t2 = t11[0]
        a1.append(t2)
    tm.close()
    tm = open("t02.txt","r")
    for lin in tm:
        temp = lin.split("=")
        t1 = temp[1]
        t11 = t1.split(".")
        t2 = t11[0]
        a1.append(t2)
    tm.close()
    tm = open("t03.txt","r")
    for lin in tm:
        temp = lin.split("=")
        t1 = temp[1]
        t11 = t1.split(".")
        t2 = t11[0]
        a1.append(t2)
    tm.close()
    if (int(a1[5]) <= 1 and int(a1[9]) <= 1 and int(a1[13]) <= 1):
        os.system("sshpass -p 'rootpassword' ssh -t pi@pi-master  'bash /kuberadir/share/freeRAM.sh'")
        os.system("sshpass -p 'rootpassword' ssh -t pi@pi01 'bash /kuberadir/share/freeRAM.sh'")
        os.system("sshpass -p 'rootpassword' ssh -t pi@pi02 'bash /kuberadir/share/freeRAM.sh'")
        os.system("sshpass -p 'rootpassword' ssh -t pi@pi03 'bash /kuberadir/share/freeRAM.sh'")
    ip = get_client_ip(request)
    logger.info('Site accessed from '+ip+' at ')
    return render_to_response('josusy_app/index.html',{'a1':a1})

#Enhanced Django function for user login --- Not yet implemented ---
@login_required
def special(request):
    return HttpResponse("You are logged in, Booyeaaahhh!!!!")

#User logout request view function
def user_logout(request):
    #logout(request)
    ip = get_client_ip(request)
    username = request.session['user']
    logoutTime = datetime.datetime.now()
    #Update time in database
    Logger.objects.filter(user=username).update(lastlogin=logoutTime)
    logger.info(request.session['user']+' logged out from '+ip+' at ')
    #Destroy user and password sessions
    del request.session['user']
    del request.session['password']
    return HttpResponseRedirect(reverse('index'))

#Changing user password by user
def ChangePassword(request):
    try:
        user = request.session['user']
        password1 = request.session['password']
        if bool(user):
            form = forms.ChangePasskey()
            if request.method == "POST":

                form = forms.ChangePasskey(request.POST)
                if form.is_valid():
                    p1 = form.data['password']
                    p2 = form.data['repassword']

                    if p1 == p2:
                        #request.session['password']=p1
                        paswd = hashlib.sha512(p1.encode())
                        password = paswd.hexdigest()
                        Logger.objects.filter(user=user).update(password=password)
                        os.system("bash /kuberadir/share/changepasswd.sh "+user+" "+password1+" "+p1+" 3")
                        request.session['password']=p1
                        return HttpResponse('<script>alert("Password succesfully updated!"); window.location.href="http://10.20.4.65:8000/jobsubmissiontype/";</script>')

                    else:
                        return HttpResponse('<script>alert("Passwords didnot match! Make sure you enter same Passwords!"); window.location.href="http://10.20.4.65:8000/changepassword/";</script>')

            return render(request,'josusy_app/changepassword.html',{'form12':form})
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for changing user password without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#Admin authentication
def auser_login(request):
    form = forms.AUserForm()
    if request.method == "POST":
        form = forms.AUserForm(request.POST)

        if form.is_valid():
            name = form.data['name']
            phd = form.data['password']
            paswd = hashlib.sha512(phd.encode())
            password = paswd.hexdigest()
            try:
                if bool((Admins.objects.get(name=name) and Admins.objects.get(password=password))):
                    request.session['admn'] = form.data['name']
                    #request.session['password'] = form.data['password']
                    ip = get_client_ip(request)
                    logger.info(request.session['admn']+' logged in as admin from '+ip+' at ')
                    return redirect('SelectTask')
                    #return HttpResponseRedirect(reverse('SelectTask'))
                else:
                    print("Email:{} & Password: {}".format(name,password))
                    ip = get_client_ip(request)
                    logger.critical(name+' tried loging in from '+ip+' at ')
                    return HttpResponse('<script>alert("Invalid Credentials! Please enter correct login credentials!"); window.location.href="http://10.20.4.65:8000/josusy_app/auser_login/";</script>')
                    #return HttpResponse("Invalid Credentials!")
            except:
                print("Admin name:{} & Password: {}".format(name,password))
                ip = get_client_ip(request)
                logger.critical(name+' tried loging in as admin from '+ip+' at ')
                return HttpResponse('<script>alert("Invalid Credentials! Please enter correct login credentials!"); window.location.href="http://10.20.4.65:8000/josusy_app/auser_login/";</script>')
                #return HttpResponse('<script>alert("Invalid Credentials! Please enter correct login credentials!"); window.location.href="http://127.0.0.1:8000/josusy_app/auser_login/";</script>')
        else:
            return render(request,'josusy_app/adminlogin.html',{'form3':form})
    else:
        return render(request,'josusy_app/adminlogin.html',{'form3':form})

#Admin Log view of DOR-JoSuSy
def AdminLogV(request):
    try:
        if bool(request.session['admn']):
            #f = open("josusy_app/log/log_file.txt","r")
            file_content = ""
            #file_content = []
            for line in reversed(list(open("josusy_app/log/log_file.txt"))):
                file_content += line.rstrip()+' \n'
            #f.close()
            context = {'file_content':file_content}
            ip = get_client_ip(request)
            logger.info('  '+request.session['admn']+'  viewed logs from  '+ip+'  at  ')
            return render(request,'josusy_app/adminlogv.html',context)
        else:
            ip = get_client_ip(request)
            logger.critical('Attempt for viewing logs without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("You dont own rights to view this page!"); window.location.href="http://10.20.4.65:8000/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#User authentication
def user_login(request):
    form = forms.UserForm()
    if request.method == "POST":
        form = forms.UserForm(request.POST)

        if form.is_valid():
            user = form.data['user']
            phd = form.data['password']
            paswd = hashlib.sha512(phd.encode())
            password = paswd.hexdigest()
            try:
                if (Logger.objects.get(user=user) and Logger.objects.get(password=password)):
                    request.session['user'] = form.data['user']
                    request.session['password'] = form.data['password']
                    ip = get_client_ip(request)
                    logger.info(request.session['user']+' logged in from '+ip+' at ')
                    return redirect('SelectSubmissionType')
                    #return HttpResponseRedirect(reverse('SelectSubmissionType'))
                else:
                    print("Email:{} & Password: {}".format(user,password))
                    ip = get_client_ip(request)
                    logger.warning(user+' tried loging in from '+ip+' at ')
                    return HttpResponse("Invalid Credentials!")
            except:
                print("User:{} & Password: {}".format(user,password))
                ip = get_client_ip(request)
                logger.warning(user+' tried loging in from '+ip+' at ')
                return HttpResponse('<script>alert("Invalid Credentials! Please enter correct login credentials!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
        else:
            return render(request,'josusy_app/login.html',{'form3':form})
    else:
        return render(request,'josusy_app/login.html',{'form3':form})

#View function for job-submission if executable file of user exist on local device
def JobDataV(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            form = forms.JobData()
            if request.method == "POST":
                form = forms.JobData(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    #queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    ncpnode = form.data['No_of_cores_per_node']
                    #hours = form.data['hour']
                    #mins =  form.data['min']
                    #myfiles = form.data['myfile']
                    csr = str(form.data['csr'])
                    nnodes=str(nnode)
                    ncpnodes=str(ncpnode)
                    hour = str(form.data['hour'])
                    min1 = str(form.data['min'])
                    #myfile= str(myfiles)
                    if request.FILES['myfile']:
                        myfile = request.FILES['myfile']
                        fs = FileSystemStorage()
                        filename = fs.save(myfile.name, myfile)

                        os.system("sudo cp "+filename+" /kuberadir/share/"+user+"/")
                        os.remove(filename)
                        file = open("xyz.sh","w")
                        file.write("#!/bin/bash \n\n #SBATCH --job-name="+jobname+" \n#SBATCH --partition=PRADYUT \n#SBATCH --nodes="+nnodes+"\n#SBATCH --ntasks-per-node="+ncpnodes+"\n#SBATCH --time="+hour+":"+min1+":00\n"+csr+"/mpirun ./"+filename+"")
                        #os.system("sudo rm -rf /home/"+user+"/xyz.sh")
                        file.close()
                        os.system("sudo cp -r xyz.sh /kuberadir/share/"+user+"/")
                        os.system("sudo cp -r xyz.sh /kuberadir/share/")
                        return redirect('http://10.20.4.65:8000/show/')
            os.system("bash /kuberadir/share/bashrc.sh "+user+" "+password+"")
            os.system("cp -r /home/"+user+"/path.txt /kuberadir/share/DOR/JoSuSy/. ")
            os.system("bash /kuberadir/share/downnodes.sh")
            #os.system("cp -r /kuberadir/share/downnodes.txt /kuberadir/share/DOR9/JoSuSy/.")
            a = []
            with open ("downnodes.txt") as i:
                for line in itertools.islice(i,1,2):
                    if 'pi' not in line:
                        print(' ')
                        a.append(0)
                    else:
                        if '[' in line:
                            u = line.split("[")
                            u11 = u[1]
                            print(u11)
                            if ',' in u11:
                                a1 = u11.split(",")
                                a11 = a1[0]
                                a.append(int(a11))
                                a12 = a1[1].split("]")
                                a13 = a12[0]

                                if '-' in a13:
                                    a14 = a13.split("-")
                                    a15 = a14[0]
                                    a16 = a14[1].split("]")
                                    a17 = a16[0]
                                    s = int(a17) - int(a15)
                                    i = 0
                                    o = int(a15)
                                    while i <= s:
                                        a.append(o)
                                        o += 1
                                        i += 1
                                else:
                                    a.append(int(a13))
                            else:
                                if '-' in u11:
                                    a1 = u11.split("-")
                                    a11 = a1[0]
                                    a12 = a1[1].split("]")
                                    a13 = a12[0]
                                    s = int(a13) - int(a11)
                                    i = 0
                                    o = int(a11)
                                    while i <= s:
                                        a.append(o)
                                        o +=1
                                        i +=1
                        else:
                            s = line[3]
                            a.append(int(s))
            a.sort()
            count = 1
            f = open("path.txt","r")
            count = 1

            if(os.stat("path.txt").st_size != 0):
                for line in f:
            	    f1 =  line.split('export PATH=')
            	    f11 = f1[1]
            	    f15 = f11.split(':')
            	    file_con = ''
            	    for i in range(len(f15)-1):
            		    file_con+= str(count)+' '+f15[i]+'\n'
            		    count+=1
            else:
                file_con = ''
            return render(request,'josusy_app/jobdatav.html',{'form1':form,'a':a, 'file_con':file_con})
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#View function for job-submission if the executable file is on the cluster home area of user
def JobDataS(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            form = forms.JobDataS()
            if request.method == "POST":
                form = forms.JobDataS(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    #queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    ncpnode = form.data['No_of_cores_per_node']
                    #walltimes = form.data['Walltime']
                    #inppaths = form.data['ipfile']
                    mypaths = form.data['myfile']
                    nnodes=str(nnode)
                    ncpnodes=str(ncpnode)
                    #walltime=str(walltimes)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])
                    csr = str(form.data['csr'])
                    #inpath=str(inppaths)
                    mypath=str(mypaths)
                    file = open("xyz.sh","w")
                    #file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+walltime+":00:00 \n\n #PBS -j oe \n\n #PBS -V \n Date \n sleep 100 \n #mpirun hostname /soft/openmpi184/bin/mpirun -np 4  --hostfile \$PBS_NODEFILE" +path+" \n\n #/soft/openmpi184/bin/mpirun -np 4 --hostfile \$PBS_NODEFILE /etc/hosts hostname")
                    file.write("#!/bin/bash \n\n#SBATCH --job-name="+jobname+"\n#SBATCH --partition=PRADYUT \n#SBATCH --nodes="+nnodes+"\n#SBATCH --ntasks-per-node="+ncpnodes+"\n#SBATCH --time="+hour+":"+min+":00\n"+csr+"/mpirun "+mypath+"")
                    #os.system("sudo rm -rf /home/"+user+"/xyz.sh")
                    file.close()
                    os.system("sudo cp -r xyz.sh /kuberadir/share/"+user+"/")
                    os.system("sudo cp -r xyz.sh /kuberadir/share/")
                    #if request.method=='POST' and 'submit' in request.POST:
                    #    file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+walltime+":00:00 \n\n #PBS -j oe \n\n #PBS -V \n Date \n sleep 100 \n #mpirun hostname /soft/openmpi184/bin/mpirun -np 4  --hostfile \$PBS_NODEFILE" +path+" \n\n #/soft/openmpi184/bin/mpirun -np 4 --hostfile \$PBS_NODEFILE /etc/hosts hostname")
                    return redirect('http://10.20.4.65:8000/show/')
            #os.system("sshpass -p "+password+" ssh -t "+user+"@pi-master ' cat .bashrc | grep "export PATH" > path.txt'")
            os.system("bash /kuberadir/share/bashrc.sh "+user+" "+password+"")
            os.system("cp -r /home/"+user+"/path.txt /kuberadir/share/DOR/JoSuSy/. ")
            os.system("bash /kuberadir/share/downnodes.sh")
            #os.system("cp -r /kuberadir/share/downnodes.txt /kuberadir/share/DOR9/JoSuSy/.")
            a = []
            with open ("downnodes.txt") as i:
                for line in itertools.islice(i,1,2):
                    if 'pi' not in line:
                        print(' ')
                        a.append(0)
                    else:
                        if '[' in line:
                            u = line.split("[")
                            u11 = u[1]
                            print(u11)
                            if ',' in u11:
                                a1 = u11.split(",")
                                a11 = a1[0]
                                a.append(int(a11))
                                a12 = a1[1].split("]")
                                a13 = a12[0]

                                if '-' in a13:
                                    a14 = a13.split("-")
                                    a15 = a14[0]
                                    a16 = a14[1].split("]")
                                    a17 = a16[0]
                                    s = int(a17) - int(a15)
                                    i = 0
                                    o = int(a15)
                                    while i <= s:
                                        a.append(o)
                                        o += 1
                                        i += 1
                                else:
                                    a.append(int(a13))
                            else:
                                if '-' in u11:
                                    a1 = u11.split("-")
                                    a11 = a1[0]
                                    a12 = a1[1].split("]")
                                    a13 = a12[0]
                                    s = int(a13) - int(a11)
                                    i = 0
                                    o = int(a11)
                                    while i <= s:
                                        a.append(o)
                                        o +=1
                                        i +=1
                        else:
                            s = line[3]
                            a.append(int(s))
            a.sort()
            count = 1
            f = open("path.txt","r")
            count = 1

            if(os.stat("path.txt").st_size != 0):
                for line in f:
                    f1 =  line.split('export PATH=')
                    f11 = f1[1]
                    f15 = f11.split(':')
                    file_con = ''
                    for i in range(len(f15)-1):
            	        file_con+= str(count)+' '+f15[i]+'\n'
            	        count+=1
            else:
                file_con= ' '
            return render(request,'josusy_app/jobdatas.html',{'form12':form,'a':a, 'file_con':file_con})
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#User home area where he/she can select how to process their job
def JobSubmissionType(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            form = forms.SelectSubmissionType()
            if request.method == "POST":

                form = forms.SelectSubmissionType(request.POST)
                if form.is_valid():
                    sch = form.data['Scheduler']
                    hte = form.data['How_to_execute']
                    lof = form.data['Location_of_file']

                    if sch == "slurm":
                        if hte == "mpi":
                            if lof == "local":
                                return redirect('http://10.20.4.65:8000/jobsubmission/')
                            else:
                                return redirect('http://10.20.4.65:8000/jobsubmissions/')
                                #return redirect('http://127.0.0.1:8000/jobsubmissions/')
                        else:
                            if lof == "local":
                                return redirect('http://10.20.4.65:8000/ssl/')
                            else:
                                return redirect('http://10.20.4.65:8000/ssc/')
                    else:
                        if hte == "mpi":
                            if lof == "local":
                                return redirect('http://10.20.4.65:8000/pml/')
                            else:
                                return redirect('http://10.20.4.65:8000/pmc/')
                        else:
                            if lof == "local":
                                return redirect('http://10.20.4.65:8000/psl/')
                            else:
                                return redirect('http://10.20.4.65:8000/psc/')

            qs = Logger.objects.filter(user=user)
            a=[p.lastlogin for p in qs]
            os.system("cat /etc/motd > motd.txt")
            f = open('motd.txt','r')
            file_content = f.read()
            f.close()

            return render(request,'josusy_app/runtypeinfo.html',{'form12':form, 'a':a,'user':user,'file_content':file_content,})
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#Admin home area
def AHome(request):
    form = forms.AdF()
    #try:
    user = request.session['admn']
    if bool(user):
        return render(request,'josusy_app/adminhome.html',)
    else:
        ip = get_client_ip(request)
        logger.critical('Attempt of accessing admin home without authentication from '+ip+' at ')
        return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
        #return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://127.0.0.1:8000/josusy_app/user_login/";</script>')
    '''except Exception as ex:
        logger.warning('Except ma aayo')
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        #return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://127.0.0.1:8000/";</script>')'''

#View function for submitting jobs that would be processed through SLURM and Sequential and executable lies on the local device
def SSL(request):
    try:
        user = request.session['user']
        password = request.session['password']
        #return HttpResponse('<script>alert("b4 if");</script>')
        if bool(user):
            form = forms.SSLF()
            if request.method == "POST":
                form = forms.SSLF(request.POST)
                if form.is_valid():
                    #return HttpResponse('<script>alert("a4 if");</script>')
                    jobname = form.data['Job_Name']
                    nnode = form.data['Number_of_Nodes']
                    #walltimes = form.data['Walltime']
                    nnodes=str(nnode)
                    #ncpnodes=str(ncpnode)
                    #walltime=str(walltimes)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])
                    #HttpResponse('<script>alert("b4 file");</script>')
                    if request.FILES['myfile']:
                        myfile = request.FILES['myfile']
                        fs = FileSystemStorage()
                        filename = fs.save(myfile.name, myfile)
                        os.system("sudo cp "+filename+" /home/"+user+"/")
                        os.remove(filename)
                        file = open("xyz.sh","w")
                        file.write("#!/bin/bash \n#SBATCH --job-name="+jobname+"\n#SBATCH --ntasks="+nnodes+"\n#SBATCH --time="+hour+":"+min+":\nsrun ./"+filename+"")
                        #os.system("sudo rm -rf /home/"+user+"/xyz.sh")
                        file.close()
                        os.system("sudo cp -r xyz.sh /kuberadir/share/"+user+"/")
                        os.system("sudo cp -r xyz.sh /kuberadir/share/")
                        return redirect('http://10.20.4.65:8000/show/')
            os.system("bash /kuberadir/share/bashrc.sh "+user+" "+password+"")
            os.system("cp -r /home/"+user+"/path.txt /kuberadir/share/DOR/JoSuSy/. ")
            os.system("bash /kuberadir/share/downnodes.sh")
            a = []

            with open ("downnodes.txt") as i:
                for line in itertools.islice(i,1,2):
                    if 'pi' not in line:
                          print(' ')
                          a.append(0)
                    else:
                       if '[' in line:
                           u = line.split("[")
                           u11 = u[1]
                           print(u11)
                           if ',' in u11:
                              a1 = u11.split(",")
                              a11 = a1[0]
                              a.append(int(a11))
                              a12 = a1[1].split("]")
                              a13 = a12[0]

                              if '-' in a13:
                                  a14 = a13.split("-")
                                  a15 = a14[0]
                                  a16 = a14[1].split("]")
                                  a17 = a16[0]
                                  s = int(a17) - int(a15)
                                  i = 0
                                  o = int(a15)
                                  while i <= s:
                                      a.append(o)
                                      o += 1
                                      i += 1
                              else:
                                  a.append(int(a13))
                           else:
                              if '-' in u11:
                                  a1 = u11.split("-")
                                  a11 = a1[0]
                                  a12 = a1[1].split("]")
                                  a13 = a12[0]
                                  s = int(a13) - int(a11)
                                  i = 0
                                  o = int(a11)
                                  while i <= s:
                                      a.append(o)
                                      o +=1
                                      i +=1
                       else:
                          s = line[3]
                          a.append(int(s))
            a.sort()
            print(a)
            count = 1
            f = open("path.txt","r")
            count = 1
            if(os.stat("path.txt").st_size != 0):
              for line in f:
                f1 =  line.split('export PATH=')
                f11 = f1[1]
                f15 = f11.split(':')
                file_con = ''
                for i in range(len(f15)-1):
                     	   file_con+= str(count)+' '+f15[i]+'\n'
             	           count+=1
            else:
                file_con = ''
            return render(request,'josusy_app/ssl.html',{'form1':form,'a':a, 'file_con':file_con})

        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#View function for submitting jobs that would be processed through SLURM and Sequential and executable lies on the cluster
def SSC(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if  bool(user):
            form = forms.SSLF()
            if request.method == "POST":
                form = forms.SSLF(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    #queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    #ncpnode = form.data['No_of_cores_per_node']
                    #walltimes = form.data['Walltime']
                    #inpath = form.data['ipfile']
                    mypath = form.data['myfile']
                    nnodes=str(nnode)
                    #ncpnodes=str(ncpnode)
                    #walltime=str(walltimes)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])

                    file = open("xyz.sh","w")
                    #file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+walltime+":00:00 \n\n #PBS -j oe \n\n #PBS -V \n Date \n sleep 100 \n #mpirun hostname /soft/openmpi184/bin/mpirun -np 4  --hostfile \$PBS_NODEFILE" +path+" \n\n #/soft/openmpi184/bin/mpirun -np 4 --hostfile \$PBS_NODEFILE /etc/hosts hostname")
                    file.write("#!/bin/bash \n#SBATCH --job-name="+jobname+"\n#SBATCH --ntasks="+nnode+"\n#SBATCH --cpus-per-task=1\n#SBATCH --time="+hour+":"+min+":00\nsrun /"+mypath+"")
                    #os.system("sudo rm -rf /home/"+user+"/xyz.sh")
                    file.close()
                    os.system("sudo cp -r xyz.sh /kuberadir/share/"+user+"/")
                    os.system("sudo cp -r xyz.sh /kuberadir/share/")
                    #if request.method=='POST' and 'submit' in request.POST:
                    #    file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+walltime+":00:00 \n\n #PBS -j oe \n\n #PBS -V \n Date \n sleep 100 \n #mpirun hostname /soft/openmpi184/bin/mpirun -np 4  --hostfile \$PBS_NODEFILE" +path+" \n\n #/soft/openmpi184/bin/mpirun -np 4 --hostfile \$PBS_NODEFILE /etc/hosts hostname")
                    return redirect('http://10.20.4.65:8000/show/')
            os.system("bash /kuberadir/share/bashrc.sh "+user+" "+password+"")
            os.system("cp -r /home/"+user+"/path.txt /kuberadir/share/DOR/JoSuSy/. ")
            os.system("bash /kuberadir/share/downnodes.sh")
            a = []
            with open ("downnodes.txt") as i:
                for line in itertools.islice(i,1,2):
                    if 'pi' not in line:

                        print(' ')
                        a.append(0)

                    else:
                        if '[' in line:

                            u = line.split("[")
                            u11 = u[1]
                            print(u11)
                            if ',' in u11:

                                a1 = u11.split(",")
                                a11 = a1[0]
                                a.append(int(a11))
                                a12 = a1[1].split("]")
                                a13 = a12[0]

                                if '-' in a13:
                                    a14 = a13.split("-")
                                    a15 = a14[0]
                                    a16 = a14[1].split("]")
                                    a17 = a16[0]
                                    s = int(a17) - int(a15)
                                    i = 0
                                    o = int(a15)
                                    while i <= s:
                                        a.append(o)
                                        o += 1
                                        i += 1
                                else:
                                    a.append(int(a13))
                            else:
                                if '-' in u11:
                                    a1 = u11.split("-")
                                    a11 = a1[0]
                                    a12 = a1[1].split("]")
                                    a13 = a12[0]
                                    s = int(a13) - int(a11)
                                    i = 0
                                    o = int(a11)
                                    while i <= s:
                                        a.append(o)
                                        o +=1
                                        i +=1
                        else:
                            s = line[3]
                            a.append(int(s))

            a.sort()
            print(a)
            count = 1
            f = open("path.txt","r")
            count = 1
            if(os.stat("path.txt").st_size != 0):
                for line in f:
                    f1 =  line.split('export PATH=')
                    f11 = f1[1]
                    f15 = f11.split(':')
                    file_con = ''
                    for i in range(len(f15)-1):
                        file_con+= str(count)+' '+f15[i]+'\n'
                        count+=1
            else:
                    file_con = ''
            return render(request,'josusy_app/ssc.html',{'form12':form,'a':a, 'file_con':file_con})

        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#View function for submitting jobs that would be processed through PBS and Multicore and executable lies on the local device
def PML(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if  bool(user):
            form = forms.PMLF()
            if request.method == "POST":
                form = forms.PMLF(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    ncpnode = form.data['No_of_cores_per_node']
                    #walltimes = form.data['Walltime']
                    nnodes=str(nnode)
                    ncpnodes=str(ncpnode)
                    #walltime=str(walltimes)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])

                    if request.FILES['myfile']:
                        #if request.FILES['ipfile']:
                            myfile = request.FILES['myfile']
                            ipfile = request.FILES['ipfile']
                            fs = FileSystemStorage()
                            filename = fs.save(myfile.name, myfile)
                            #filename2= fs.save(ipfile.name, ipfile)
                            os.system("sudo cp "+filename+" /home/"+user+"/")
                            os.system("sudo cp "+filename2+" /home/"+user+"/")
                            os.remove(filename)
                            os.remove(filename2)
                            file = open("pbs.sh","w")
                            file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+hour+":"+min+":00 \n mpirun "+filename+"")
                            file.close()
                            os.system("sudo cp -r pbs.sh /kuberadir/share/"+user+"/")
                            return redirect('http://10.20.4.65:8000/readscript/')

            return render(request,'josusy_app/pml.html',{'form1':form})
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#View function for submitting jobs that would be processed through PBS and Multicore and executable lies on the Cluster
def PMC(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            form = forms.PMLF()
            if request.method == "POST":
                form = forms.PMLF(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    ncpnode = form.data['No_of_cores_per_node']
                    #walltimes = form.data['Walltime']
                    #inppath = form.data['ipfile']
                    mypath = form.data['myfile']
                    nnodes=str(nnode)
                    ncpnodes=str(ncpnode)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])

                    #walltime=str(walltimes)
                    file = open("pbs.sh","w")
                    file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+hour+":"+min+":00 \n mpirun "+mypath+"")
                    #file.write("#!/bin/bash \n\n #SBATCH --job-name="+jobname+"\n\n #SBATCH --ntasks="+nnodes+"\n\n #SBATCH --cpus-per-task="+ncpnodes+"\n\n #SBATCH --time="+walltime+"\n\n source "+inpath+" \n mpirun /"+mypath+"")
                    #os.system("sudo rm -rf /home/"+user+"/xyz.sh")
                    file.close()
                    os.system("sudo cp -r pbs.sh /kuberadir/share/"+user+"/")
                    #os.system("sudo cp -r pbs.sh /kuberadir/share/")
                    #if request.method=='POST' and 'submit' in request.POST:
                    #    file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+walltime+":00:00 \n\n #PBS -j oe \n\n #PBS -V \n Date \n sleep 100 \n #mpirun hostname /soft/openmpi184/bin/mpirun -np 4  --hostfile \$PBS_NODEFILE" +path+" \n\n #/soft/openmpi184/bin/mpirun -np 4 --hostfile \$PBS_NODEFILE /etc/hosts hostname")
                    return redirect('http://10.20.4.65:8000/readscript/')
            return render(request,'josusy_app/pmc.html',{'form12':form})

        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#View function for submitting jobs that would be processed through PBS and Sequential and executable lies on the Local device
def PSL(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if  bool(user):
            form = forms.PSLF()
            if request.method == "POST":
                form = forms.PSLF(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    #queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    #walltimes = form.data['Walltime']
                    nnodes=str(nnode)
                    #walltime=str(walltimes)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])

                    if request.FILES['myfile']:
                        #if request.FILES['ipfile']:
                        myfile = request.FILES['myfile']
                        ipfile = request.FILES['ipfile']
                        fs = FileSystemStorage()
                        filename = fs.save(myfile.name, myfile)
                        filename2= fs.save(ipfile.name, ipfile)
                        os.system("sudo cp "+filename+" /home/"+user+"/")
                        os.system("sudo cp "+filename2+" /home/"+user+"/")
                        os.remove(filename)
                        os.remove(filename2)
                        file = open("pbs.sh","w")
                        file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q \n\n #PBS -l select=1 :ncpus=1\n\n #PBS -l walltime="+hour+":"+min+":00 \n\n source "+filename2+" \n mpirun "+filename+"")
                        file.close()
                        os.system("sudo cp -r pbs.sh /kuberadir/share/"+user+"/")
                        return redirect('http://10.20.4.65:8000/readscript/')

            return render(request,'josusy_app/psl.html',{'form1':form})
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#View function for submitting jobs that would be processed through PBS and Sequential and executable lies on the Cluster
def PSC(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            form = forms.PSLF()
            if request.method == "POST":
                form = forms.PSLF(request.POST)
                if form.is_valid():
                    jobname = form.data['Job_Name']
                    #queue = form.data['Queue']
                    nnode = form.data['Number_of_Nodes']
                    #ncpnode = form.data['No_of_cores_per_node']
                    #walltimes = form.data['Walltime']
                    #inppath = form.data['ipfile']
                    mypath = form.data['myfile']
                    #nnodes=str(nnode)
                    #ncpnodes=str(ncpnode)
                    #walltime=str(walltimes)
                    hour = str(form.data['hour'])
                    min = str(form.data['min'])

                    file = open("pbs.sh","w")
                    file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q queue\n\n #PBS -l select=1:ncpus=1\n\n #PBS -l walltime="+hour+":"+min+":00 \n\n mpirun "+mypath+"")
                    #file.write("#!/bin/bash \n\n #SBATCH --job-name="+jobname+"\n\n #SBATCH --ntasks=1\n\n #SBATCH --cpus-per-task=1\n\n #SBATCH --time="+walltime+"\n\n source "+inpath+" \n mpirun /"+mypath+"")
                    #os.system("sudo rm -rf /home/"+user+"/xyz.sh")
                    file.close()
                    os.system("sudo cp -r pbs.sh /kuberadir/share/"+user+"/")
                    #os.system("sudo cp -r xyz.sh /kuberadir/share/")
                    #if request.method=='POST' and 'submit' in request.POST:
                    #    file.write("#!/bin/bash \n\n #PBS -N "+jobname+"\n\n #PBS -q "+queue+"\n\n #PBS -l select="+nnodes+":ncpus="+ncpnodes+"\n\n #PBS -l walltime="+walltime+":00:00 \n\n #PBS -j oe \n\n #PBS -V \n Date \n sleep 100 \n #mpirun hostname /soft/openmpi184/bin/mpirun -np 4  --hostfile \$PBS_NODEFILE" +path+" \n\n #/soft/openmpi184/bin/mpirun -np 4 --hostfile \$PBS_NODEFILE /etc/hosts hostname")
                    return redirect('http://10.20.4.65:8000/readscript/')
            return render(request,'josusy_app/psc.html',{'form12':form})

        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for jobsubmission without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please login for submitting jobsssss!"); window.location.href="http://10.20.4.65:8000/josusy_app/user_login/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#This view function will display the job id of the submitted job.
def display(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            os.system("cd /kuberadir/share")
            os.system("sshpass -p '"+password+"' ssh -t "+user+"@10.20.4.65  'cd /kuberadir/share/"+user+"/ && sbatch xyz.sh > id.txt'")
            os.system("cp -r /kuberadir/share/"+user+"/id.txt /kuberadir/share/DOR/JoSuSy")
            f = open("id.txt","r")
            file_content = f.read()
            f.close()
            context = {'file_content':file_content}
            ip = get_client_ip(request)
            logger.info(request.session['user']+' submitted job number '+file_content+' from '+ip+' at ')
            return render(request,'josusy_app/display.html',context)
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for viewing job status without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please do access site in proper flow!");</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http ://10.20.4.65:8000/";</script>')

#This view function will will display the PBS Script that will be generated, because we dont have a PBS environment
def ReadScript(request):
    try:
        user = request.session['user']
        password = request.session['password']
        if bool(user):
            f0 = open("pbs.sh","r")
            file_content = f0.read()
            f0.close()
            context = {'file_content':file_content}
            ip = get_client_ip(request)
            logger.warning(request.session['user']+' submitted job from '+ip+' at ')
            return render(request,'josusy_app/display.html',context)
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for viewing job status without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please do access site in proper flow!");</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#It is a basic Job Monitoring function, it shows the ongoing jobs
def squeue(request):
    try:
        user = request.session['user']
        if bool(user):
            os.system("squeue > squeue.txt")
            f = open('squeue.txt','r')
            file_content = f.read()
            f.close()
            context = {'file_content':file_content}
            ip = get_client_ip(request)
            logger.debug('Cluster status checked from '+ip+' at ')
            return render(request,'josusy_app/squeue.html',context)
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for viewing job status without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please do access site in proper flow!"); window.location.href="http://10.20.4.65:8000/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')

#It is to show list of files in user's directory

def user_files(request):
    try:
        user = request.session['user']
        if bool(user):
            os.system("bash /kuberadir/share/list.sh "+user+"")
            f = open('files.txt','r')
            file_content = f.read()
            f.close()
            context = {'file_content':file_content}
            ip = get_client_ip(request)
            logger.debug('Cluster status checked from '+ip+' at ')
            return render(request,'josusy_app/user_files.html',context)
        else:
            ip = get_client_ip(request)
            logger.warning('Attempt for viewing user_files without authentication from '+ip+' at ')
            return HttpResponse('<script>alert("Please do access site in proper flow!"); window.location.href="http://10.20.4.65:8000/";</script>')
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        ip = get_client_ip(request)
        logger.critical(''+message+' on '+ip+' at ')
        return HttpResponse('<script>alert("Sorry for there was some issue! \n We will solve it soon!"); window.location.href="http://10.20.4.65:8000/";</script>')
