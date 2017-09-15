'''
Created on 03.11.2016

@author: mark
'''
from email import email
import imaplib
import smtplib
import mailbox
import datetime
from ConfigParser import RawConfigParser
import sys
import StringIO
import subprocess
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from os.path import basename
import uuid
import select
import fcntl
import os
import json
import time
import gnupg
import re
import logging
from logging.handlers import RotatingFileHandler
import exceptions



class Config:

    SECTION = "mail2Shell"
    STRING_KEYS=["mailServer", "smtpServer", "username", "password", "magicKey", "trustedSender", "msgFormat", "logFileName", \
                 "workDir", "path2Shell", "keys", "gpgBinary"]
    INT_KEYS=["maxFilesize", "keepRunning"]
    BOOLEAN_KEYS=["enableLogging", "enableGPG", "allowOnlyGPG", "verifySignature"]

    DEFAULTS={"enableLogging" :"yes",
              "logFileName" : "/tmp/mail2shell.log",
              "maxFilesize" : 1000000,
              "msgFormat" : "%(asctime)s, %(levelname)s, %(module)s, %(lineno)d, %(message)s",
              "path2Shell" : "/bin/sh",
              "keepRunning" : 0,
              "enableGPG" : "True",
              "keys": "./keys",
              "allowOnlyGPG" : "False",
              "verifySignature" : "True",
              "gpgBinary" : "/usr/local/bin/gpg"
              }

    
    def __init__(self, cfgFile):
        self.cfg=RawConfigParser(Config.DEFAULTS)
        _=self.cfg.read(cfgFile)

    def hasKey(self, dct, key):
        k=key.upper()
        for d in dct:
            if d.upper() == k:
                return d
        return None

    def __getattr__(self, name):
        key=self.hasKey(Config.STRING_KEYS, name)
        if not key is None:
            return self.cfg.get(Config.SECTION, key)
        key=self.hasKey(Config.INT_KEYS, name)
        if not key is None:
            return self.cfg.getint(Config.SECTION, key)
        key=self.hasKey(Config.BOOLEAN_KEYS, name)
        if not key is None:
            return self.cfg.getboolean(Config.SECTION, key)
        return None



class DateTimeEncoder(json.JSONEncoder):

        
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return {
                '__type__' : 'seconds',
                'seconds' : time.mktime(obj.timetuple()),
            }   
        else:
            return json.JSONEncoder.default(self, obj)
    
class DateTimeDecoder(json.JSONDecoder):
    
    def __init__(self, *args, **kargs):
        json.JSONDecoder.__init__(self, object_hook=self.dict_to_object,
                             *args, **kargs)
    
    def dict_to_object(self, d): 
        if '__type__' not in d:
            return d

        return datetime.datetime.fromtimestamp(d['seconds'])

    
    
    
    

class Mail2Shell:
    
    thisApp="mail2Shell"
    stopShell='###'
    
    def __init__(self):
        self.startTime=datetime.datetime.now()
        config=Config("./mail2Shell.ini")
        try:
            self.logFilename=config.logFileName
            self.log=logging.Logger("m2s")
            loghdl=RotatingFileHandler(self.logFilename, 'a', config.maxFileSize, 4)
            loghdl.setFormatter(logging.Formatter(config.msgFormat))
            loghdl.setLevel(logging.DEBUG)
            self.log.addHandler(loghdl)
        except exceptions.Exception, e:
            print "[MS21005] Daemon was not able to initialize logging system. Reason: %s" % e
            sys.exit()

    
    
    def retrieveMail(self):
        config=Config("./mail2Shell.ini")
        tmp=config.trustedSender
        trustedSender=tmp.split(";")
        if config.enableGPG:
            gpgProperlyConfigured=False
            fingerprints={}
            keyDir=config.keys
            gpgPath=os.path.join(keyDir, "gpgHome")
            os.system('rm -rf ' + gpgPath)
            #TODO REMOVE binary or make it co nfig
            gpg = gnupg.GPG(homedir=gpgPath, binary=config.gpgBinary, options='')
            
            if(os.path.exists(keyDir)):
                for s in trustedSender:
                    fName=os.path.join(keyDir, s+".asc")
                    if not(os.path.exists(fName)):
                        pass
                        #print "WARN: cannot handle gpg message for %s" % (s)
                    else:
                        f=open(fName)
                        tmp=f.read()
                        f.close()
                        res=gpg.import_keys(tmp);
                        fingerprints[s.upper()]=res.fingerprints[0]
                        
                fName=os.path.join(keyDir, config.userName + ".asc")
                if not(os.path.exists(fName)):
                    self.log.error("gpg will not work as there is no key information for the main user %s" % (config.userName))
                else:
                    f=open(fName)
                    tmp=f.read()
                    f.close() 
                    impRes=gpg.import_keys(tmp)
                    fingerprints[config.userName.upper()]=impRes.fingerprints[0]
                    isPrivateKey=False
                    for x in impRes.results:
                        if x['status']=='Contains private key\n':
                            isPrivateKey=True
                            break
                    if not(isPrivateKey):
                        self.log.error("Key for %s contains no private key" % (config.userName))
                    else:
                        gpgProperlyConfigured=True
            else:
                self.log.error("key Directory is missing (%s) " % (keyDir))
        
        if config.allowOnlyGPG and not(gpgProperlyConfigured):
            self.log.error( "GPG not configured properly, but set up to work w/ encrypted messages only - exiting")
            return        
                
        mail=imaplib.IMAP4_SSL(config.mailServer)
        mail.login(config.userName, config.password)
        lst=mail.list()
        mail.select("inbox")
        
        result, data = mail.uid('search', None, '(UNSEEN SUBJECT "' + config.magicKey + '")') # (ALL/UNSEEN)
        i = len(data[0].split())

        for x in range(i):
            latest_email_uid = data[0].split()[x]
            #print latest_email_uid
            result, email_data = mail.uid('fetch', latest_email_uid, '(RFC822)')
            # result, email_data = conn.store(num,'-FLAGS','\\Seen') 
            # this might work to set flag to seen, if it doesn't already
            raw_email = email_data[0][1]
            raw_email_string = raw_email.decode('utf-8')
            email_message = email.message_from_string(raw_email_string)

            # Header Details
            date_tuple = email.Utils.parsedate_tz(email_message['Date'])
            if date_tuple:
                local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
                local_message_date = "%s" %(str(local_date.strftime("%a, %d %b %Y %H:%M:%S")))
            emailFrom = str(email.Header.make_header(email.Header.decode_header(email_message['From'])))
            email_to = str(email.Header.make_header(email.Header.decode_header(email_message['To'])))
            subject = str(email.Header.make_header(email.Header.decode_header(email_message['Subject'])))

            found=False
            for ts in trustedSender:
                if ts.upper() in emailFrom.upper():
                    found=True
                    p = re.compile('[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', re.IGNORECASE)
                    returnMail=re.findall(p, ts)[0]
                    break
            if not(found):
                continue
            
            self.log.debug("Received email from %s" % (returnMail))
            
            # Body details
            hasErr=False
            errMessage=""   
            attachments=[]
            attachmentsIn={}
            isEncryptedMail=False
            done=False
            while not(done) and not(hasErr):
                for part in email_message.walk():
                    #print part.get_content_type()
                    if part.get_content_type() == "multipart/encrypted":
                        if not(returnMail.upper() in fingerprints):
                            errMessage = "Encrypted mail cannot be processed as key information is missing for %s" % (returnMail)
                            self.log.error(errMessage)
                            hasErr=True
                            break
                        if not(config.userName.upper() in fingerprints):
                            errMessage = "Encrypted mail cannot be processed as key information is missing for %s" % (config.userName)
                            self.log.error(errMessage)
                            hasErr=True
                            break
                        isEncryptedMail=True
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8')
                        done=True
                    elif part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                        if isEncryptedMail:
                            if part.get_content_type()=="application/octet-stream":
                                encMsg=part.get_payload(decode=True)
                                print len(encMsg)
                                decMsg = gpg.decrypt(encMsg)
                                if decMsg.ok:
                                    if decMsg.signature_id is None:
                                        print "Message is not signed"
                                        if config.verifySignature:
                                                print "ERROR: email is not signed (missing)"
                                                hasErr=True
                                                errMessage = "Missing signature"
                                        else:
                                            print "Message is not signed"
                                    else:
                                        if fingerprints[returnMail.upper()]==decMsg.fingerprint:
                                            print "Message is correctly signed by " + returnMail
                                        else:
                                            if config.verifySignature:
                                                print "ERROR: email is not signed by trusted sender (fingerprint not matching)"
                                                hasErr=True
                                                errMessage = "Wrong signature"
                                            else:
                                                print "WARN: email is not signed by trusted sender"
                                    #print decMsg
                                    #TODO check error message
                                    email_message = email.message_from_string(decMsg.data)
                                else:
                                    hasErr=True
                                    errMessage=decMsg.stderr
                                break
                        else:
                            attachmentsIn[part.get_filename()]=part.get_payload(decode=True)
                    else:
                        continue
                    
            if not(hasErr):        
                lines = body.split('\n')
                retDataPlain=""
                retDataHtml="<br>"
                process=subprocess.Popen(config.path2Shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                for l in lines:
                    l=l.strip()
                    if len(l)==0:
                        continue
                    if l.startswith('++'):
                        break
                    if l.startswith('+'):
                        if l.upper().startswith("+GET"):
                            fls=l[4:].split()
                            for fl in fls:
                                if os.path.exists(fl) and os.path.isfile(fl):
                                    bytes_read = open(fl, "rb").read()
                                    att=MIMEApplication(bytes_read, Name=basename(fl))
                                    att['Content-Disposition'] = 'attachment; filename="%s"' % basename(fl)
                                    attachments.append(att)
                                    retDataPlain+="## Attached file " + fl + "\n"
                                    retDataHtml+="## Attached file " + fl + "<br>"
                                else:
                                    retDataPlain+="## Requested file " + fl + " does not exist or is not a file\n"
                                    retDataHtml+="## Requested file " + fl + " does not exist or is not a file<br>"
                        if l.upper().startswith("+PUT"):
                            fls=l[4:].split()
                            for fl in fls:
                                if attachmentsIn.has_key(basename(fl)):
                                    fp = open(fl, 'wb')
                                    fp.write(attachmentsIn[basename(fl)])
                                    fp.close()
                                    retDataPlain+="## Stored file " + fl + "\n"
                                    retDataHtml+="## Stored file " + fl + "<br>"
                                else:
                                    retDataPlain+="## Attachment not found " + fl + "\n"
                                    retDataHtml+="## Attachment not found " + fl + "<br>"
                                    
                    else:
                        retDataPlain+=returnMail + "> " + l + "\n"
                        retDataHtml+=returnMail + ">" + l + "<br>"
                        process.stdin.write(l + '\n')
                        fds=select.select([process.stdout, process.stderr], [], [], 1)
                        outData=""
                        for f in fds[0]:
                            fl = fcntl.fcntl(f, fcntl.F_GETFL)
                            fcntl.fcntl(f, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                            outData+=f.read()
                            retDataPlain+=outData + "\n" 
                            retDataHtml+=outData.replace('\n', '<br>') + "<br>"
                process.communicate()
            else:
                retDataPlain="Error occured: \n" + errMessage
                retDataHtml="Error occured: \n" + errMessage.replace('\n', '<br>')

            smtp = smtplib.SMTP_SSL(config.smtpServer)
            smtp.set_debuglevel(0)
            smtp.login(config.userName, config.password)
                    
            from_addr = config.userName
            to_addr = returnMail
                    
            msg = MIMEMultipart('alternative')
            htmlData = "<html><head></head><body style=\"background:#6E6E6E\"><font face=\"Courier New\"><span style=\"color:#16CC13\"/>" \
                        + retDataHtml + "</p></font></body></html>"
            part1=MIMEText(retDataPlain, "plain")
            part2=MIMEText(htmlData, "html")
            if len(attachments)==0:
                msg.attach(part1)
                msg.attach(part2)
                msgToSend=msg
            else:
                msgMixed=MIMEMultipart('mixed')    
                msg.attach(part1)
                msg.attach(part2)
                msgMixed.attach(msg)
                for att in attachments:
                    msgMixed.attach(att)
                msgToSend=msgMixed
            
            msgToSend['Subject'] = config.magicKey
            msgToSend['From'] = config.userName
            msgToSend['To'] = returnMail
            
            if isEncryptedMail:
                self.log.debug("Preparing encrypted mail")
                encMsg=gpg.encrypt(msgToSend.as_string(), fingerprints[returnMail.upper()], always_trust=True, default_key=fingerprints[config.userName.upper()])
                msg = MIMEMultipart('encrypted')
                part1 = MIMEText('Version: 1\n', 'application/pgp-encrypted')
                att=MIMEApplication(encMsg.data, Name='encrypted.asc')
                att['Content-Disposition'] = 'inline; filename="encrypted.asc"'
                att['Content-Description'] = 'OpenPGP encrypted message'
                msg.attach(part1)
                msg.attach(att)
                msgToSend=msg
                msgToSend['From'] = config.userName
                msgToSend['To'] = returnMail
                msg['Subject']=config.magicKey
            
            self.log.debug("Sending mail to %s" % (to_addr))        
            smtp.sendmail(from_addr, to_addr, msgToSend.as_string())
            smtp.quit()    


if __name__ == '__main__':
    m2s=Mail2Shell()
    m2s.retrieveMail()