#!/usr/bin/env python
# -*- coding: utf-8 -*-

#__Author__ = virink
#__Blog__   = http://www.virink.cn

import os
import sys
import commands
import re
import time
import base64
import platform

waf='''PD9waHANCmZ1bmN0aW9uIHNjYW5mSW5qZWN0KCl7DQoJJGMgPSAnJzsNCgkkYyAuPSAnR0VUOicuJF9TRVJWRVJbIlFVRVJZX1NUUklORyJdLiJcclxuIjsNCgkkYyAuPSAnUE9TVDonLmZpbGVfZ2V0X2NvbnRlbnRzKCJwaHA6Ly9pbnB1dCIpLiJcclxuIjsNCgkkYyAuPSAnQ09PS0lFOic7DQoJZm9yZWFjaCgkX0NPT0tJRSBhcyAkayA9PiAkdikNCgkJJGMgLj0gIiRrPSR2JiI7DQoJJGMgPSB1cmxkZWNvZGUoJGMpOw0KCSRjID0gc3Vic3RyKCRjLDAsc3RybGVuKCRjKS0xKTsNCglpZihwcmVnX21hdGNoKCIvc2VsZWN0fGluc2VydHx1cGRhdGV8ZGVsZXRlfGFuZHxvcnxldmFsfFwnfFwvXCp8XCp8XC5cLlwvfFwuXC98dW5pb258aW50b3xsb2FkX2ZpbGV8b3V0ZmlsZXxzdWJ8aGV4LyIsJGMpKXtzYXZlaW5qZWN0bG9nKCRjKTt9IA0KfQ0KZnVuY3Rpb24gc2F2ZWluamVjdGxvZygkbG9nKXsNCgloZWFkZXIoJ1NRTFdhZjpNYWRlIEJ5IFZpcmluaycpOw0KCSRsb2cgPSAnZmlsZTonLiRfU0VSVkVSWyJTQ1JJUFRfTkFNRSJdLiJcclxucGxheWxvYWQ6Ii4kbG9nLiJcclxuXHJcbiI7DQoJJGZwID0gZm9wZW4oJy90bXAvdmR1bl93YWZfbG9nLnR4dCcsICdhKycpOw0KCWZ3cml0ZSgkZnAsICRsb2cpOw0KCWZjbG9zZSgkZnApOw0KfQ0Kc2NhbmZJbmplY3QoKTsNCj8+'''

shellwaf='''PD9waHANCmZ1bmN0aW9uIHNjYW5mSW5qZWN0KCl7DQoJJGMgPSAnJzsNCgkkYyAuPSAnR0VUOicuJF9TRVJWRVJbIlFVRVJZX1NUUklORyJdLiJcclxuIjsNCgkkYyAuPSAnUE9TVDonLmZpbGVfZ2V0X2NvbnRlbnRzKCJwaHA6Ly9pbnB1dCIpLiJcclxuIjsNCgkkYyAuPSAnQ09PS0lFOic7DQoJZm9yZWFjaCgkX0NPT0tJRSBhcyAkayA9PiAkdikNCgkJJGMgLj0gIiRrPSR2JiI7DQoJJGMgPSB1cmxkZWNvZGUoJGMpOw0KCSRjID0gc3Vic3RyKCRjLDAsc3RybGVuKCRjKS0xKTsNCglzYXZlaW5qZWN0bG9nKCRjKTsNCn0NCmZ1bmN0aW9uIHNhdmVpbmplY3Rsb2coJGxvZyl7DQoJaGVhZGVyKCdTaGVsbFdhZjpNYWRlIEJ5IFZpcmluaycpOw0KCSRsb2cgPSAnZmlsZTonLiRfU0VSVkVSWyJTQ1JJUFRfTkFNRSJdLiJcclxucGxheWxvYWQ6Ii4kbG9nLiJcclxuXHJcbiI7DQoJJGZwID0gZm9wZW4oJy90bXAvdmR1bl9zaGVsbF9sb2cudHh0JywgImErIik7DQoJZndyaXRlKCRmcCwgJGxvZyk7DQoJZmNsb3NlKCRmcCk7DQoJZXhpdCgpOw0KfQ0Kc2NhbmZJbmplY3QoKTsNCj8+'''

rulelist = [
    '(\$_(GET|POST|REQUEST)\[.{0,15}\]\s{0,10}\(\s{0,10}\$_(GET|POST|REQUEST)\[.{0,15}\]\))',
    '(base64_decode\([\'"][\w\+/=]{200,}[\'"]\))',
    '(eval(\s|\n)*\(base64_decode(\s|\n)*\((.|\n){1,200})',
    '((eval|assert)(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
    '(\$[\w_]{0,15}(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
    '(call_user_func\(.{0,15}\$_(GET|POST|REQUEST))',
    '(preg_replace(\s|\n)*\(.{1,100}[/@].{0,3}e.{1,6},.{0,10}\$_(GET|POST|REQUEST))',
    '(wscript\.shell)',
    '(cmd\.exe)',
    '(shell\.application)',
    '(documents\s+and\s+settings)',
    '(system32\(\))',
    '(serv-u)',
    '(phpspy)',
    '(jspspy)',
    '(webshell)',
    '(Program\s+Files)'
]

def ScanShell(path):  
    for root,dirs,files in os.walk(path):
        for filespath in files:
            if filespath.find('.virinkbak')>0:
                continue
            if os.path.getsize(os.path.join(root,filespath))<1024000 and filespath.find('.php')>0:
                file= open(os.path.join(root,filespath))
                filestr = file.read()
                file.close()
                for rule in rulelist:
                    result = re.compile(rule).findall(filestr)
                    if result:
                        print '\t\t=> File : '+os.path.join(root,filespath)
                        print '\t\t=> Malicious code : '+str(result[0])[0:200]
                        os.rename(os.path.join(root,filespath),os.path.join(root,filespath)+'.virinkbak')
                        f= open(os.path.join(root,filespath),'w')
                        f.write(base64.b64decode(shellwaf))
                        f.close()
                        ff = open(runroot+'/vdun_webshell.txt','a+')
                        ff.write(os.path.join(root,filespath)+' => '+os.path.join(root,filespath)+'.virinkbak\r\n')
                        ff.close()
                        print '\t\t=> Replaced by sqlwaf file'
                        print '\t\t=> '+os.path.join(root,filespath)+' => '+os.path.join(root,filespath)+'.virinkbak\r\n\r\n'
                        break
#Find the PHP configuration file path
def getPhpIniPath():
    phpIniPath = runCmd('php -i |grep "Loaded Configuration File"')
    phpIniPath = phpIniPath.replace('Loaded Configuration File => ','')
    print '\tphpIniPath : '+phpIniPath+'\r\n'
    return phpIniPath

#Change the PHP configuration for auto_prepend_file,allow_url_fopen
def changePhpIni( iniPath ):
    fp = open(iniPath,'r')
    t = fp.read()
    fp.close()
    fp = open(iniPath,'w')
    try:
        r = re.compile('auto_prepend_file\s=\s(.*)').findall(t)
        if len(r)==1:
            t = t.replace(r[0],'')
        t = t.replace('auto_prepend_file =','auto_prepend_file = "/tmp/vdun/inject.php"')
        t = t.replace('allow_url_fopen = On','allow_url_fopen = Off')
        r = re.compile(';include_path\s=\s"\.:.*"|include_path\s=\s"\.:.*"').findall(t)
        x = r[0]
        r = x
        r = re.compile('include_path\s=\s"(.*)"').findall(r)
        r = r[0]
        if r.find(':/tmp/vdun') == -1:
            t = t.replace(x,'include_path = "'+r+':/tmp/vdun"')
        fp.write(t)
    finally:
        fp.close()
        print '\tChanged php.ini for auto_prepend_file,allow_url_fopen,include_path'
        print '\t\t@ => '+runCmd('cat '+iniPath+' |grep "auto_prepend_file"')
        print '\t\t@ => '+runCmd('cat '+iniPath+' |grep "allow_url_fopen"')
        print '\t\t@ => '+runCmd('cat '+iniPath+' |grep "include_path = \\".:"')
        print '\tPlease restart Nginx or Apache, and php-fpm!!!\r\n'

def runCmd(cmd):
    return commands.getoutput(cmd)

def writePhpSqlWaf():
    fp = open('/tmp/vdun/inject.php','w')
    try:
        fp.write(base64.b64decode(waf))
    finally:
        fp.close()
    print '\tWrite "'+runroot+'/vdun/inject.php" is ok\r\n'

##############################################
if __name__ == '__main__':
    print '''\r\n\t\t#########################################
\t\t#   AppName :   PHPWaf 1.0              #
\t\t#   Author  :   Virink                  #
\t\t#   Blog    :   http://www.virink.cn    #
\t\t#########################################\r\n'''
    if platform.system() != 'Linux':
        print '\tPlease Run in Linux'
        exit()
    if len(sys.argv) != 2:
        print '\tRun error\r\n\tUsage:python '+sys.argv[0]+' website\r\n\teg : python '+sys.argv[0]+' /root/www\r\n'
        exit()
    webroot = sys.argv[1]
    runroot = '/tmp'
    #Initialization, to create a working directory
    if not os.path.exists(runroot+'/vdun'):
        os.mkdir(runroot+'/vdun')
    print '\tPHPWaf_logfiles directory : '+runroot
    print '\t\t@ => logfiles Replaced : '+runroot+'/vdun_webshell.txt'
    print '\t\t@ => logfiles Playload : '+runroot+'/vdun_waf_log.txt'
    print '\t\t@ => logfiles ShellLog : '+runroot+'/vdun_shell_log.txt\r\n'
    #Write to sqlwaf file
    writePhpSqlWaf()
    #Change the PHP configuration
    changePhpIni(getPhpIniPath())
    #Start scan webshell
    print '\tStart scan webshell'
    while(True):
        ScanShell(webroot)
        time.sleep(1)
