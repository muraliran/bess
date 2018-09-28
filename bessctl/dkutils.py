#
# Utility for managing docker containers
#
# (C) Copyright Futurewei Inc., 2018-2019
# Author: Murali Rangachari
#
#

import os
import subprocess, shlex

def CheckIfExists(dkname):
    dk_cmd_args = ['docker', 'ps', '-a']
    dk_chk_args = ['grep', '-o', dkname]
    dk_cmd = subprocess.Popen(dk_cmd_args,
                              stdout=subprocess.PIPE)
    dk_chk = subprocess.Popen(dk_chk_args, stdin=dk_cmd.stdout,
                              stdout=subprocess.PIPE)
    dk_cmd.stdout.close()
    output, error = dk_chk.communicate()
    return (output.rstrip() == dkname)

def CheckIfRunning(dkname):
    dk_cmd_args = ['docker', 'ps']
    dk_chk_args = ['grep', '-o', dkname]
    dk_cmd = subprocess.Popen(dk_cmd_args,
                              stdout=subprocess.PIPE)
    dk_chk = subprocess.Popen(dk_chk_args, stdin=dk_cmd.stdout,
                              stdout=subprocess.PIPE)
    dk_cmd.stdout.close()
    output, error = dk_chk.communicate()
    return (output.rstrip() == dkname)

def CreateInstance(dkname):
    if CheckIfExists(dkname):
        StartInstance(dkname)
    else:
        dk_create_args = ['docker', 'run', '-itd', '--name', dkname, '--hostname',
                          dkname, '--privileged', 'ubuntu:trusty']
        dk_create = subprocess.Popen(dk_create_args,
                                     stdout=subprocess.PIPE)
        output, error = dk_create.communicate()

def StartInstance(dkname):
    if CheckIfRunning(dkname):
        #do nothing
        print("Already running")
    else:
        dk_start_args = ['docker', 'start', dkname]
        dk_start = subprocess.Popen(dk_start_args,
                                    stdout=subprocess.PIPE)
        output,error = dk_start.communicate()

def DeleteInstance(dkname):
    if CheckIfExists(dkname):
        if CheckIfRunning(dkname):
            dk_stop_args = ['docker', 'stop', dkname]
            dk_stop = subprocess.Popen(dk_stop_args, stdout=subprocess.PIPE)
            output, error = dk_stop.communicate()
        dk_del_args = ['docker', 'rm', dkname]
        dk_del = subprocess.Popen(dk_del_args, stdout=subprocess.PIPE)
        output, error = dk_del.communicate()
    else:
        print("Instance " + dkname + " does not exist")

def AddRoute(dkname, netw, ipaddr, dev):
    route_cmd_args = ['docker', 'exec', '-it', dkname, 'ip', 'route', 'add',
                      netw, 'via', ipaddr, 'dev', dev]
    route_cmd = subprocess.Popen(route_cmd_args,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
    output, error = route_cmd.communicate()
    if error:
        print("Error setting route: " + route_cmd.returncode)
        print(error.strip())
