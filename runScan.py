#!/usr/bin/python
# ---------------------------------------------------------------
# https://github.com/infosecwatchman/Auvant
# Wrapper for OpenVAS 7.0.3 = 127.0.0.1:9392/help/about.html
# 5.4.2020
# ---------------------------------------------------------------
# Credit:
# inspired and adapted from code16.py
# on https://code610.blogspot.com/2016/12/automated-scans-with-openvas-and-kali.html
# ---------------------------------------------------------------
# Author:
# InfoSecWatchman
# Twitter: @infosecwatchman
# Github: github.com/infosecwatchman
# ---------------------------------------------------------------
# Please do not use for illegal purposes.
# ---------------------------------------------------------------
# changelog:
#   5.4.2020 -
#       initial ground breaking
#   5.11.2020 -
#       Update to include some fault tolerance when checking openvas for updates.
#
# ---------------------------------------------------------------
# Example:
# root@:/home# python ./runScan.py NameOfScan 127.0.0.1 Standard
# root@:/home# python ./runScan.py NameOfScan 127.0.0.1 Windows
# root@:/home# python ./runScan.py NameOfScan 127.0.0.1 Linux
# ---------------------------------------------------------------
# Make sure to edit the following section before running:
# Credentials:
Username = 'admin'
Password = 'password'
OpenVasServer = '127.0.0.1'
WindowsSMBCred = 'f7e2761f-48fa-467d-a9b0-e07b89e693bb'
LinuxSSHCred = 'a277e72c-ea14-49a6-bf14-40757fb121be'
##############################

import thread
import sys
import subprocess
import time
from datetime import datetime
import re

def hello():

    print ('-------------------------------------------------------------------------------------')
    print ("                          Auvant: The Wrapper for OpenVAS 7.0.3")
    print ('-------------------------------------------------------------------------------------')
    print ("              If Target ID = 400, exit script. ^C to exit, and clear all Targets. ")
    print ("                            You may need to clear tasks.")
    print ('-------------------------------------------------------------------------------------\n')

def StandardOpenVasScan(name, target):
    name = name
    target = target

    #Delete Target with same name (ie. previous target)
    GetTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " -T | grep " + name + " | cut -d' ' -f1"
    TargetID = subprocess.check_output([GetTarget], shell=True)
    TargetID = TargetID.replace("\n", "")
    DeleteTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml='<delete_target target_id=\"" + TargetID + "\"/>'"
    subprocess.check_output([DeleteTarget], shell=True)

    #Create Target
    CreateTarget = "omp -h "+OpenVasServer+" -u "+Username+" -w "+Password+" --xml='<create_target> <name>"+name+"</name> <hosts>"+target+"</hosts> </create_target>' | sed \"s/.*id=//g\" | cut -d'\"' -f 2 "
    TargetID = subprocess.check_output([CreateTarget],shell=True)
    TargetID = TargetID.replace("\n", "")
    print("\nTarget ID  = " + TargetID + "\n")
    return TargetID

def CredentialedWindowsOpenVasScan(name, target):
    name = name
    target = target

    #Delete Target with same name (ie. previous target)
    GetTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " -T | grep -w " + name + " | cut -d' ' -f1"
    TargetID = subprocess.check_output([GetTarget], shell=True)
    TargetID = TargetID.replace("\n", "")
    DeleteTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml='<delete_target target_id=\"" + TargetID + "\"/>'"
    subprocess.check_output([DeleteTarget], shell=True)

    #Create Target
    CreateTarget = "omp -h "+OpenVasServer+" -u "+Username+" -w "+Password+" --xml='<create_target> <name>"+name+"</name> <hosts>"+target+"</hosts><smb_credential id=\""+WindowsSMBCred+"\"/> </create_target>' | sed \"s/.*id=//g\" | cut -d'\"' -f 2 "
    TargetID = subprocess.check_output([CreateTarget],shell=True)
    TargetID = TargetID.replace("\n", "")
    print ("\nTarget ID  = "+TargetID+"\n")
    return TargetID

def CredentialedLinuxOpenVasScan(name, target):
    name = name
    target = target

    #Delete Target with same name (ie. previous target)
    GetTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " -T | grep " + name + " | cut -d' ' -f1"
    TargetID = subprocess.check_output([GetTarget], shell=True)
    TargetID = TargetID.replace("\n", "")
    DeleteTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml='<delete_target target_id=\"" + TargetID + "\"/>'"
    subprocess.check_output([DeleteTarget], shell=True)

    #Create Target
    CreateTarget = "omp -h "+OpenVasServer+" -u "+Username+" -w "+Password+" --xml='<create_target> <name>"+name+"</name> <hosts>"+target+"</hosts><ssh_credential id=\""+LinuxSSHCred+"\"/> </create_target>' | sed \"s/.*id=//g\" | cut -d'\"' -f 2 "
    TargetID = subprocess.check_output([CreateTarget],shell=True)
    TargetID = TargetID.replace("\n", "")
    print("\nTarget ID  = " + TargetID + "\n")
    return TargetID

def ContinueScan(name, TargetID):
    name = name
    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y-%H-%M")

    #Create Task at 'Full and fast' scan level (ie. Config id = daba56c8-73ec-11df-a475-002264764cea)
    print("Creating Task...")
    CreateTask = "omp -h "+OpenVasServer+" -u "+Username+" -w "+Password+" --xml='<create_task><name>"+name+"</name><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><target id=\""+TargetID+"\"/></create_task>' | sed \"s/.*id=//g\" | cut -d'\"' -f 2 "
    TaskID = subprocess.check_output([CreateTask],shell=True)
    TaskID = TaskID.replace("\n","")

    #Start the task that was created above
    print("Starting Task...")
    StartTaskCMD = "omp -h "+OpenVasServer+" -u "+Username+" -w "+Password+" --xml='<start_task task_id=\""+TaskID+"\"/>'"
    StartTask = subprocess.check_output([StartTaskCMD], shell=True)

    #Check if Task is done
    time.sleep(5)
    CheckDoneCMD = "omp -h "+OpenVasServer+" -u "+Username+" -w "+Password+" -G | grep "+TaskID
    try:
        CheckDone = subprocess.check_output([CheckDoneCMD], shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        pass
    print("Checking if task is complete...")
    time.sleep(225)

    while 'Done' not in CheckDone:
        print("...")
        time.sleep(35)
        try:
            CheckDone = subprocess.check_output([CheckDoneCMD], shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            print(".....")
            time.sleep(60)
            pass
        if 'Done' in CheckDone:
            print("Getting CSV report")

            #Get Report ID and format it
            GetReportID = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml=' <get_tasks task_id=\"" + TaskID + "\"/>' -i | grep -i 'report id' -m 1| cut -d '\"' -f 2"
            ReportID = subprocess.check_output([GetReportID], shell=True)
            ReportID = ReportID.replace("\n","")

            #Report CSV report (To change report, change c1645568-627a-11e3-a660-406186ea4fc5 to your desired report format's ID)
            GetReportCMD = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml='<get_reports report_id=\"" + ReportID + "\" format_id=\"c1645568-627a-11e3-a660-406186ea4fc5\"/>' -i | sed -n 2p | sed \"s/.*c5\\\">//g\" | base64 -d > "+name+"-"+dt_string+".csv"
            GetReport = subprocess.check_output([GetReportCMD], shell=True)
            time.sleep(3)
            return GetReport

            #Cleanup task and Target.
            CleanupTask = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml='<delete_task task_id=\"" + TaskID + "\"/>'"
            subprocess.check_output([CleanupTask], shell=True)
            print("Report wrote to "+name+"-"+dt_string+".csv")
            DeleteTarget = "omp -h " + OpenVasServer + " -u " + Username + " -w " + Password + " --xml='<delete_target target_id=\"" + TargetID + "\"/>'"
            subprocess.check_output([DeleteTarget], shell=True)
            break

def check(Ip):
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

    if (re.search(regex, Ip)):
        pass
    else:
        print("Invalid Ip address")
        sys.exit()

def StartScan(name, ip, scantype):
    check(ip)

    if scantype == "Standard":
        hello()
        print ("Creating Noncredentialed Target...")
        ContinueScan(name, StandardOpenVasScan(name, ip))

    elif scantype == "Windows":
        hello()
        print ("Creating Credentialed Windows Target...")
        ContinueScan(name, CredentialedWindowsOpenVasScan(name, ip))

    elif scantype == "Linux":
        hello()
        print ("Creating Credentialed Linux Target...")
        ContinueScan(name, CredentialedLinuxOpenVasScan(name, ip))

    else:
        print ("Invalid Command Syntax, please see example.")
        sys.exit()

StartScan(sys.argv[1], sys.argv[2], sys.argv[3])
