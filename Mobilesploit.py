"""
							 Mobilesploit
	MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMM                MMMMMMMMMM
	MMMN$                           vMMMM
	MMMNl  MMMMM             MMMMM  JMMMM
	MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
	MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
	MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
	MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
	MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
	MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
	MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
	MMMNI  WMMMM   MMMMMMM   MMMMM  JMMMM
	MMMMR  ?MMNM             MMMMM  dMMMM
	MMMMNm `?MMM    MMnMM    MMMM` dMMMMM
	MMMMMMN  ?MM   MM"M"MM   MM?  NMMMMMN
	MMMMMMMMNe    MM"   "MM    JMMMMMNMMM
	MMMMMMMMMMNm,            eMMMMMNMMNMM
	MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
	MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM

Disclaimers:
	Mobilesploit is NOT an original idea-based application! Mobilesploit is based off of Metasploit by Rapid7! Mobilesploit is a non-profit penetration testing software that is open source! Mobilesploit does not contain any source code from Metasploit!
	
	Please support Metasploit's Official Release! (http://metasploit.com)
	
	Copyright (C) 2006-2018, Rapid7 LLC
	Metasploit EULA (Legal Reference):
		https://information.rapid7.com/terms
	Copyright (C) 2018, Savage Security Technology Mobilesploit

About:
	Coding: Python 2.7.11
	Developer: @Russian_Otter
	Requirements: Pythonista 3 for iOS

Encoding:
	Indent/Tab: 2
	Encoding: UTF-8

API Script:
	Check "API.md" for how to set up your own exploits that Mobilesploit can read!

"""

import sys, console, time, os, requests, textwrap, re, threading, runpy, urllib, zipfile, shutil

version = "v3.0.0-iOSMobile"
pause = False
haslaunched = False
postamount = 0
loc = ""
sets = {"slowsearch":"true"}
var = []
profiles = {
	"exploits":{},
	"auxiliary":{},
	"payloads":{},
	"posts":{}
}

def fdir(name, start="./", get=False, end=".py"):
	null = []
	if sets["slowsearch"] == "true" and haslaunched:
		slow = True
	else:
		slow = False
	for root, dirs, files in os.walk(start):
		for file in files:
			if slow:
				time.sleep(0.0002)
			if "exploit" in root or "payload" in root or "auxiliary" in root:
				if "" in file and "__" not in file and file.endswith(end):
					epath = (os.path.join(root, file))
					if get == True:
						if epath.count("/") > 1 and name in epath:
							null.append(epath)
					elif epath.count("/") > 1 and name in epath:
						return epath
	return null

logo = """\
	MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMM                 MMMMMMMMMM
	MMMN$                           vMMMM
	MMMNl  MMMMM             MMMMM  JMMMM
	MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
	MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
	MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
	MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
	MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
	MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
	MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
	MMMNI  WMMMM   MMMMMMM   MMMMM  JMMMM
	MMMMR  ?MMNM             MMMMM  dMMMM
	MMMMNm `?MMM    MMnMM    MMMM` dMMMMM
	MMMMMMN  ?MM   MM"M"MM   MM?  NMMMMMN
	MMMMMMMMNe    MM"   "MM    JMMMMMNMMM
	MMMMMMMMMMNm,            eMMMMMNMMNMM
	MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
	MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM\
"""

def linecount(segment):
	spaces = []
	spacenote = 0
	for s in segment:
		if s == " ":
			spacenote += 1
		else:
			spaces.append(spacenote)
			spacenote = 0
	try:
		for _ in range(len(segment.strip())):
			spaces.remove(0)
	except:
		pass
	return spaces

def print_banner():
	console.set_color(0.85,0.85,0.85)
	if os.uname()[-1][6] == "7":
		console.set_font("Menlo",13.5)
	else:
		console.set_font("Menlo",10)
	print "\n\t"+(" "*10)+"Mobilesploit v3.0"
	linenum = 0
	for line in logo.split("\n"):
		linenum += 1
		nspace = linecount(line)
		bspace = line.split()
		char = 0
		if len(bspace) < 3:
			console.set_color(0,0,0.86)
			sys.stdout.write(line)
		if len(bspace) >= 3:
			for _ in bspace:
				if char == 0:
					sys.stdout.write("\t")
				if char == 0 or char == 4:
					console.set_color(0,0,0.86)
					sys.stdout.write(_)
				else:
					console.set_color(0.85,0.85,0.85)
					if bspace.index(_) == len(bspace)-1:
						console.set_color(0,0,0.86)
					sys.stdout.write(_)
				try:
					sys.stdout.write(" "*nspace[char])
				except:
					pass
				char += 1
		print
	console.set_color(0.85,0.85,0.85)
	print "\t       https://metasploit.com\n"

def statistics(update=False):
	if not update:
		if os.uname()[-1][6] == "7":
			console.set_font("Menlo",10)
		else:
			console.set_font("Menlo",8)
		b1 = "       =[ mobilesploit %s       "%version
		b1 = b1+(" "*(59-len(b1)-1))+"]"
		b2 = "+ -- --=[ %s exploits - %s auxiliary - %s posts      "%(len(profiles["exploits"]), len(profiles["auxiliary"]), postamount)
		b2 = b2+(" "*(59-len(b2)-1))+"]"
		b3 = "+ -- --=[ %s payloads - 0 encoders - 0 nops          "%(len(profiles["payloads"]))
		b3 = b3+(" "*(59-len(b3)-1))+"]"
		b4 = "+ -- --=[ Free Metasploit Pro trail: http://r-7.co/trymsp ]"
		print "\n"+b1+"\n"+b2+"\n"+b3+"\n"+b4+"\n"
		console.set_font("Menlo", size)
	if update:
		try:
			udcode = requests.get("https://raw.githubusercontent.com/RussianOtter/Mobilesploit/master/update.ms", timeout=3).text
			#exec udcode
			f = open("update.ms","w")
			f.write(udcode)
			f.close()
		except Exception as e:
			pass

def clean_folders():
	for root, dirs, files in os.walk("./"):
		if not os.listdir(root) and not dirs:
			os.rmdir(root)

def full_banner():
	print_banner()
	statistics()

def mobilesplot_startup():
	console.set_color(0.85,0.85,0.85)
	if os.uname()[-1][6] == "7":
		console.set_font("Menlo",11.5)
	else:
		console.set_font("Menlo",10)
	print " - Please Support Metasploit's Official Release! -\n"
	run = "[*] Starting the Mobilesploit Framework Console..."
	runu = run.upper()
	while not haslaunched:
		for x in range(len(run)):
			s = "\r"+run[0:x]+runu[x]+run[x+1:]
			sys.stdout.write(s)
			sys.stdout.flush()
			if haslaunched:
				break
			time.sleep(0.08)
	time.sleep(1)
	console.clear()
	full_banner()

def reformat_program(program):
	sourcecode = open(program).read()
	if "__mbsargs__" not in sourcecode:
		if "sys" not in sourcecode:
			sourcecode = "import sys\n"+sourcecode
		if "import sys\n" in sourcecode:
			sourcecode = sourcecode.replace("import sys\n","import sys\ntry:\n\tif type(__mbsargs__) == list:\n\t\tsys.argv = __mbsargs__\nexcept:\n\tpass\n")
		elif "import sys," in sourcecode or ", sys\n" in sourcecode or ", sys, " in sourcecode:
			f = sourcecode.split("\n")
			line = 0
			found = False
			for s in f:
				if ("import sys," in s or ", sys\n" in s or ", sys, " in s) and "import " in s:
					found = True
					break
				line += 1
			if found:
				sourcecode = sourcecode.replace(f[line], f[line]+"\n"+"try:\n\tif type(__mbsargs__) == list:\n\t\tsys.argv = __mbsargs__\nexcept:\n\tpass\n")
		sourcecode = sourcecode.replace("sys.exit", "sys.xt").replace("exit", "sys.exit").replace("sys.xt", "sys.exit")
		sourcecode = sourcecode.replace(",\n",",")
		ofile = open(program,"w")
		ofile.write(sourcecode)
		ofile.close()

def MetaThread(app, post):
	try:
		pause = True
		print
		runpy.run_path(app, init_globals={"__mbsargs__":post}, run_name="__main__")
		print
		time.sleep(0.5)
		pause = False
	except Exception as e:
		sys.stderr.write(" => %s\n"%str(e))

def auto_payload(name, size):
	au = "  "+name+" "*(19-len(name)) + str(size)+"b"
	print au

def auto_option(name, cset, req):
	if len(name+cset)+1 > 25:
		name += " "
		cset += " "
		stbl = "  " + name + " "*(9-len(name)) + cset + " "*(26-len(name+cset)) + req + " "*(36-len(name+cset+req))
	elif len(name) > 8:
		name += " "
		stbl = "  " + name + " "*(9-len(name)) + cset + " "*(26-len(name+cset)) + req + " "*(8-len(req)+2)
	else:
		stbl = "  " + name + " "*(9-len(name)) + cset + " "*(15-len(cset)+2) + req + " "*(8-len(req)+2)
	return stbl

def auto_info(name,rank):
	stbl = "  " + name + " "*(11-len(name)+4) + rank + " "*(8-len(rank)+4)
	return stbl

def format_publisher(exploit, gather=False):
	f = open(exploit).read()
	taglines = []
	for _ in f.split("\n"):
		if _.startswith("#"):
			taglines.append(_)
	nlines = []
	for _ in taglines:
		nlines.append(_.replace(" :",":"))
	taglines = nlines
	exploitname = exploit.split("/")[-1].split(".py")[0]
	expro = {
		"name":"Unknown",
		"date":"Unknown",
		"author":"Unknown",
		"vendor":"Unknown",
		"software":"Unknown",
		"version":"Unknown",
		"cve":"Unknown",
		"license":"Unknown",
		"platform":"Unknown",
		"rank":"normal",
		"file":exploit,
		"appname":exploitname,
		"taginfo":False
	}
	for tag in taglines:
		tag = tag.replace("https://","%tt%")
		tag = tag.replace("http://","%tt%")
		tag = tag.replace(": ",":").replace("  ","")
		tag = tag.replace("\n","").replace("--","")
		tag = tag.replace("  ","").replace("=","")
		tag = tag.replace("..", "").replace("09".decode("hex"),"")
		tag = tag.replace("##","")
		if "exploit title" in tag.lower() or "title" in tag.lower():
			if ":" in tag and expro["name"] == "Unknown" and "," not in tag:
				ntag = " ".join(tag.split(":")[1:])
				while ntag.startswith(" "):
					ntag = ntag[1:]
				expro.update({"name":ntag})
		if expro["name"] == "Unknown" and tag[:-3] in tag.title() and (tag.count("a") > 1 or tag.count("e") > 1) and tag.count(" ") >= 3:
			ntag = tag.strip("# ")
			while ntag.startswith(" "):
				ntag = ntag[1:]
			ntag = ntag.split(":")
			if "Exploit Name" in ntag[0] and len(ntag)>1:
				ntag = ntag[1]
			else:
				ntag = ntag[0]
			expro.update({"name":ntag})
		if "date" in tag.lower() or "released" in tag.lower():
			if ":" in tag and expro["date"] == "Unknown":
				expro.update({"date":tag.split(":")[1]})
		if "author" in tag.lower():
			if ":" in tag and expro["author"] == "Unknown":
				expro.update({"author":" ".join(tag.split(":")[1:])})
		if "vendor" in tag.lower():
			if ":" in tag and expro["vendor"] == "Unknown":
				expro.update({"vendor":" ".join(tag.split(":")[1:])})
		if "software" in tag.lower():
			if ":" in tag and expro["software"] == "Unknown":
				expro.update({"software":" ".join(tag.split(":")[1:])})
		if "version" in tag.lower():
			if ":" in tag and expro["version"] == "Unknown":
				expro.update({"version":" ".join(tag.split(":")[1:])})
		if "license" in tag.lower():
			if ":" in tag and expro["license"] == "Unknown":
				expro.update({"license":" ".join(tag.split(":")[1:])})
		if "platform" in tag.lower():
			if ":" in tag and expro["platform"] == "Unknown":
				expro.update({"platform":" ".join(tag.split(":")[1:])})
		if "cve" in tag.lower():
			if ":" in tag and expro["cve"] == "Unknown":
				cve = " ".join(tag.split(":")[1:])
				if len(cve) < 15:
					expro.update({"cve":cve})
		if "rank" in tag.lower():
			if ":" in tag and expro["rank"] == "normal":
				expro.update({"rank":" ".join(tag.split(":")[1:])})
	if expro.values().count("Unknown") >= 6:
		nl = {"name":"Unknown"}
		expro.update({"taginfo":"\n".join(taglines)})
		for val in expro:
			if expro[val] != "Unknown":
				nl.update({val:expro[val]})
		expro = nl
	if "exploit" in exploit:
		profiles["exploits"].update({exploitname: expro})
	elif "auxiliary" in exploit:
		profiles["auxiliary"].update({exploitname: expro})
	elif "payload" in exploit:
		profiles["payload"].update({exploitname: expro})
	if expro["taginfo"] != False and not gather:
		print "\nPublisher Information for %s" %exploit
		print
		print "     Module:", exploit
		print "       Rank:", expro["rank"]
		print "   Tag Info:\n", "\n".join(taglines)
		print
	elif not gather:
		print "\nPublisher Information for %s" %exploit
		print
		print "       Name:", expro["name"]
		print "     Module:", exploit
		print "   Platform:", expro["platform"].replace("%tt%","https://")
		print "    Version:", expro["version"]
		print "     Vendor:", expro["vendor"].replace("%tt%","https://")
		print "    License:", expro["license"]
		print "   Software:", expro["software"].replace("%tt%","https://")
		print "        CVE:", expro["cve"]
		print "       Rank:", expro["rank"]
		print "  Disclosed:", expro["date"]
		print "         By:", expro["author"].replace("%tt%","https://")
		print

def collectprograms(reload=False):
	sets = {"slowsearch":"true"}
	if not haslaunched or reload:
		globals()["postamount"] = len(fdir("", get=True, end=".txt"))
	for program in fdir("", get=True):
		format_publisher(program, True)
		reformat_program(program)
	time.sleep(1.2)
	globals()["haslaunched"] = True

def descript(program, category="exploits", prof=False):
	if ".py" not in program:
		program += ".py"
	if category == "exploit":
		category = "exploits"
	inside = open(program).read()
	if not prof:
		prof = profiles[category][program.split("/")[-1].split(".py")[0]]
	if "description='" in inside:
		m = re.search('description=\'(.+?)\'', inside)
	elif "description=\"" in inside:
		m = re.search('description="(.+?)"', inside)
	elif "description = '" in inside:
		m = re.search('description = \'(.+?)\'', inside)
	elif "description = \"" in inside:
		m = re.search('description = "(.+?)"', inside)
	else:
		m = False
	if m:
		description = m.group(1)
	else:
		description = prof["name"]
	if prof:
		baseinfo = auto_info(prof["appname"], prof["rank"])
	screensize = console._get_screen_size()
	if screensize[0]/float(screensize[1]) >= 1.0:
		width = 80
	else:
		width = 49
	wrapper = textwrap.TextWrapper(initial_indent=baseinfo, width=width, subsequent_indent=" "*len(baseinfo))
	print wrapper.fill(description)

def programopt(program):
	name = program.split("/")[-1].split(".py")[0]
	category = program.split("/")[-2]
	print "\nModule Options (%s)\n"%program.strip("./").strip(".py")
	print "  Name     Current Setting  Required  Description"
	print "  ----     ---------------  --------  -----------"
	inside = open(program).read()
	arglines = []
	for line in inside.split("\n"):
		if ".add_argument" in line:
			arglines.append(line)
	for line in arglines:
		arg, default, nsa, nsahlp = None, None, None, None
		if ".add_argument('" in line:
			try: nsa = re.search(".add_argument\('(.+?)'", line).group(1)
			except: pass
			if 'help="' in line:
				try: nsahlp = re.search('help="(.+?)"', line).group(1).replace("(","[").replace(")","]")
				except: pass
			elif "help='" in line:
				try: nsahlp = re.search("help='(.+?)'", line).group(1)
				except: pass
		elif '.add_argument("' in line:
			try: nsa = re.search('.add_argument\("(.+?)"', line).group(1)
			except: pass
			if 'help="' in line:
				try: nsahlp = re.search('help="(.+?)"', line).group(1)
				except: pass
			elif "help='" in line:
				try: nsahlp = re.search("help='(.+?)'", line).group(1)
				except: pass
		if "--" in line:
			try: arg = re.search("--(.+?)'", line).group(1)
			except: pass
			if not arg:
				try: arg = re.search('--(.+?)"', line).group(1)
				except: pass
		if 'help="' in line:
			try: hlp = re.search('help="(.+?)"', line).group(1)
			except: pass
		elif "help='" in line:
			try: hlp = re.search("help='(.+?)'", line).group(1)
			except: pass
		if "default=" in line:
			try: default = re.search("default=(.+?)\)", line).group(1)
			except: pass
			if not default:
				try: default = re.search("default=(.+?),", line).group(1)
				except: pass
		if arg:
			arg = arg.replace('"',"").replace("'","")
			if not default:
				if "action=" in line:
					default = "FalseNSA"
					required = "no"
				else:
					default = ""
					required = "yes"
			else:
				if default == "True" and "action=" in line:
					default = "TrueNSA"
				required = "no"
			if not hlp:
				hlp = ""
			if arg in sets.keys():
				default = sets[arg]
			default = default.replace('"',"").replace("'","")
			baseinfo = auto_option(arg, default, required)
			screensize = console._get_screen_size()
			if screensize[0]/float(screensize[1]) >= 1.0:
				width = 80
			else:
				width = 49
			wrapper = textwrap.TextWrapper(initial_indent=baseinfo, width=width, subsequent_indent=" "*len(baseinfo))
			print wrapper.fill(hlp)
		if nsa and nsa.startswith("-") == False:
			nsa = nsa.replace('"',"").replace("'","")
			if nsa in sets.keys():
				default = sets[nsa]
			else:
				default = ""
			default = default.replace('"',"").replace("'","")
			baseinfo = auto_option(nsa, default, "yes")
			screensize = console._get_screen_size()
			if screensize[0]/float(screensize[1]) >= 1.0:
				width = 80
			else:
				width = 49
			wrapper = textwrap.TextWrapper(initial_indent=baseinfo, width=width, subsequent_indent=" "*len(baseinfo))
			if nsahlp:
				print wrapper.fill(nsahlp.strip("\n\t").replace("  ",""))
			else:
				print wrapper.fill(nsa.strip("\n\t").replace("  ",""))
	print

def parmcheck(program, form=False):
	name = program.split("/")[-1].split(".py")[0]
	category = program.split("/")[-2]
	inside = open(program).read()
	reqparm = []
	allparm = []
	nsaparm = []
	arglines = []
	defualtarg = {}
	for line in inside.split("\n"):
		if ".add_argument" in line:
			arglines.append(line)
	for line in arglines:
		arg, default, nsa = None, None, None
		if ".add_argument('" in line:
			try: nsa = re.search(".add_argument\('(.+?)'", line).group(1)
			except: pass
		elif '.add_argument("' in line:
			try: nsa = re.search('.add_argument\("(.+?)"', line).group(1)
			except: pass
		if "--" in line:
			try:
				arg = re.search("--(.+?)'", line).group(1)
				if "required=True" in line and ".add_argument(" in line:
					reqparm.append(arg)
			except: pass
		elif "--" in line:
			try:
				arg = re.search('--(.+?)"', line).group(1)
				if "required=True" in line and ".add_argument(" in line:
					reqparm.append(arg)
			except: pass
		if "default=" in line:
			default = re.search("default=(.+?)\)", line)
			if default:
				default = default.group(1)
				if arg:
					defualtarg.update({arg:default})
				if nsa:
					defualtarg.update({nsa:default})
			else:
				default = re.search("default=(.+?),", line)
				if default:
					default = default.group(1)
					if arg:
						defualtarg.update({arg:default})
					if nsa:
						defualtarg.update({nsa:default})
		if nsa:
			nsa = nsa.replace('"',"").replace("'","")
			if ("action=" in line or "default=" in line) and nsa.startswith("-") == False:
				nsaparm.append(nsa)
				if "action=" in line:
					defualtarg.update({nsa:"FalseNSA"})
			elif nsa not in reqparm and nsa.startswith("-") == False and "action=" not in line:
				reqparm.append(nsa)
				nsaparm.append(nsa)
		if arg:
			arg = arg.replace('"',"").replace("'","")
			allparm.append(arg)
			if not default:
				default = None
				required = "yes"
				if arg not in reqparm and "action=" not in line:
					reqparm.append(arg)
			else:
				required = "no"
	canex = True
	for a in reqparm:
		if a not in sets.keys():
			canex = False
	if form and canex:
		listedargs = []
		for a in reqparm:
			if a not in nsaparm:
				a = a.replace('"',"").replace("'","")
				listedargs.append("--"+a)
				listedargs.append(sets[a].replace('"', "").replace("'",""))
		for d in defualtarg:
			d = d.replace('"',"").replace("'","")
			listedargs.append("--"+d)
			listedargs.append(defualtarg[d].replace('"',"").replace("'",""))
		for n in nsaparm:
			if sets[n] == "FalseNSA" or sets[n] == "TrueNSA":
				listedargs.append(n)
			else:
				listedargs.append(sets[n])
		return [sys.argv[0]]+listedargs
	return canex

def show_payload():
	print "\nAvailable Payloads"
	print "==================\n"
	print "  Name               Size"
	print "  ----               ----"
	try:
		for _ in os.listdir("./payload"):
			if "." in _ and "__" not in _:
				payinfo = _, len(open("./payload/"+_).read())
				auto_payload(payinfo[0], payinfo[1])
	except:
		pass
	print

def show_auxiliary():
	print "\nAvailable Auxiliary"
	print "====================\n"
	print "  Name           Rank        Description"
	print "  ----           ----        -----------"
	try:
		for program in profiles["auxiliary"]:
			descript(profiles["auxiliary"][program]["file"],"auxiliary", profiles["auxiliary"][program])
	except:
		pass
	print 

def auto_cmd(cmd, description):
	stbl = "  " + cmd + " "*(7-len(cmd)+7) + description + " "*(11-len(description))
	time.sleep(0.001)
	print stbl

def meta_launch(app, post):
	if os.path.isfile(app):
		thread = threading.Thread(target=MetaThread, args=(app, post,))
		thread.daemon = True
		thread.start()
		while pause:
			pass
		time.sleep(0.1)
		print
	else:
		sys.stderr.write(" => Invalid program file (does not exist)\n")

def extended_cmd(cmd, post, loc):
	if cmd == "force" and post[0] == "update":
		if raw_input("Are you sure you want to reinstall packages [y/n]") == "y":
			statistics(True)
	elif cmd == "show" and ("auxiliary" in post[0] or "aux" in post[0]):
		show_auxiliary()
	elif cmd == "exploit":
		try:
			if parmcheck(loc):
				meta_launch(loc, parmcheck(loc,True))
			else:
				sys.stderr.write(" => Too few arguments (check options)\n")
		except Exception as e:
			sys.stderr.write(" => %s\n"%str(e))
	elif cmd == "show" and ("exploits" in post[0] or "exp" in post[0]):
		print "\nAvailable Exploits"
		print "==================\n"
		print "  Name           Rank        Description"
		print "  ----           ----        -----------"
		try:
			for program in profiles["exploits"]:
				descript(profiles["exploits"][program]["file"],"exploits", profiles["exploits"][program])
				if sets["slowsearch"] == "true":
					time.sleep(0.001)
		except:
			pass
		print
	elif (cmd == "info" and len(post) > 0) or (cmd == "info" and len(loc) > 4):
		try:
			if len(loc) > 4:
				infop = loc
			else:
				infop = fdir(post[0])
			if type(infop) == str:
				format_publisher(infop)
		except:
			pass
	elif cmd == "show" and post[0] == "options" and loc != "":
		programopt(loc)
	elif cmd == "get" and ("options" in post or "opt" in post):
		for _ in var:
			print _.replace("%20%"," ")
	elif cmd == "show" and (post[0] == "payload" or post[0] == "payloads"):
		show_payload()
	elif cmd == "set":
		if len(post) > 1:
			if ("".join(post).count("'")/2.0).is_integer() or ("".join(post).count('"')/2.0).is_integer():
				fpost = " ".join(post)
				try:
					rep = re.search("'(.+?)'", fpost).group(1)
					fpost = fpost.replace(rep,rep.replace(" ","%20%").replace('\'',''))
				except:
					try:
						rep = re.search('"(.+?)"', fpost).group(1)
						fpost = fpost.replace(rep,rep.replace(" ","%20%").replace("\"",""))
					except:
						rep = ""
				post = fpost.split(" ")
			post[1] = post[1].replace("%20%"," ")
			sets.update({post[0]:post[1]})
			tran = post[0]+" => "+post[1]
			var.append(tran)
			print tran
	elif cmd == "version":
		statistics()
	elif cmd == "reload_all":
		collectprograms(True)
		clean_folders()
	if cmd == "help" or cmd == "?":
		time.sleep(0.4)
		print "\nCore Commands"
		print "==============\n"
		print "  Command       Description"
		print "  -------       -----------"
		auto_cmd("?","Help Menu")
		auto_cmd("help","Help Menu")
		auto_cmd("back","Move back from the current context")
		auto_cmd("exit","Exit the console")
		auto_cmd("get","Display set variables <options>")
		auto_cmd("set","Set parmeters and arguments")
		auto_cmd("info","Get program information <file>")
		auto_cmd("use","Select module by name")
		auto_cmd("show","<options|payloads|auxiliary|exploits>")
		auto_cmd("size","Changes font size")
		auto_cmd("clear","Resets screen activity")
		auto_cmd("banner","Display awesome mobilesploit banner")
		auto_cmd("remove","Delete Variable")
		auto_cmd("force update","Forcefully Reinstall Packages")
		auto_cmd("reload_all","Refresh all modules")
		auto_cmd("version","Display framework and library numbers")
		auto_cmd("uninstall","Uninstall file type <rb|sh|...>")
		auto_cmd("read","Show contents of file")
		auto_cmd("install","Download database <exploitdb>")
		auto_cmd("rename","Rename application <program> <name>")
		auto_cmd("add_header","Adds comment header to program <program> <header>")
		auto_cmd("locate","Find program <program>")
		print

def commandline(loc=""):
	loc = loc.replace("./","")
	while 1:
		console.write_link("msf","")
		if loc == "":
			sys.stdout.write(" ")
		else:
			loco = loc.split("/")
			sys.stdout.write(" %s(" %(loco[0]))
			if console._get_screen_size()[0] > 500 or len("/".join(loco[1:])) < 23:
				sys.stderr.write("%s"%("/".join(loco[1:]).replace(".py","")))
			else:
				sys.stderr.write("%s" %(loco[-1].replace(".py","")))
			sys.stdout.write(") ")
		try:
			cmd = raw_input("> ")
			cmd,post = cmd.split(" ")[0].lower(),cmd.split(" ")[1:]
		except:
			print
			cmd, post = "",[""]
		if cmd == "clear":
			console.clear()
			full_banner()
		elif cmd == "locate" and len(post) > 0:
			print " =>",fdir(post[0])
		elif cmd == "use" and len(post) == 1:
			try:
				commandline(fdir(post[0]))
			except Exception as e:
				sys.stderr.write(" => %s\n"%str(e))
				pass
		elif cmd == "back":
			break
		elif cmd == "exit": 
			exit()
		elif cmd == "banner":
			full_banner()
		elif cmd == "rename" and len(post) > 1:
			tgpg = fdir(post[0])
			if len(post[1]) > 3:
				if not post[1].endswith(".py"):
					post[1] += ".py"
				tf = "/".join(tgpg.split("/")[:-1])+ "/" + post[1]
				shutil.move(tgpg, tf)
				collectprograms()
				sys.stderr.write("[*] ")
				sys.stdout.write("Renamed %s -> %s\n"%(tgpg, tf))
		elif cmd == "search" and post[0] == "posts" and len(post) > 1:
			selected = []
			for ps in fdir("", get=True, end=".txt"):
				inf = open(ps).read()
				for srch in post[1:]:
					if srch in inf:
						selected.append(ps)
						break
			tmsg = "Search Results for (%s)"%" ".join(post[1:])
			print
			print tmsg
			print "="*len(tmsg)
			print
			print "  File\n  ----\n"
			for pst in selected:
				print " ",pst
			print
		elif cmd == "search" and len(post) > 0:
			tmsg = "Search Results for (%s)"%post[0]
			print
			print tmsg
			print "="*len(tmsg)
			print
			print "  Name           Rank        Description"
			print "  ----           ----        -----------"
			for prgrm in fdir(post[0], get=True):
				descript(prgrm, prgrm.split("/")[1])
			print
		elif cmd == "size" and len(post) == 0:
			console.set_font("Menlo", size)
		elif cmd == "size" and len(post[0]) > 1:
			try:
				console.set_font("Menlo", int(post[0]))
				globals()["size"] = int(post[0])
			except:
				pass
		elif cmd == "add_header" and len(post) > 1:
			if len(post[0]) > 3:
				tgf = fdir(post[0])
				if os.path.isfile(tgf) and len(post[1]) > 2:
					acode = open(tgf).read()
					acode = "# "+post[1]+"\n"+acode
					f = open(tgf,"w")
					f.write(acode)
					f.close()
					sys.stderr.write("[*] ")
					sys.stdout.write("Header added to %s\n"%tgf)
		elif cmd == "python" and len(post) > 0:
			if post[0].endswith(".py") and os.path.isfile(post[0]):
				try:
					t = threading.Thread(target=MetaThread, args=(post[0]," ".join(post[1:],)))
					t.name = "python_app"
					t.daemon = True
					t.start()
					while pause and "python_app" in threading._active:
						time.sleep(0.5)
					time.sleep(1.2)
					print
				except Exception as e:
					sys.stderr.write(" => %s\n"%str(e))
					print
			else:
				sys.stderr.write(" => Invalid file path\n")
		elif cmd == "remove" and len(post) > 0:
			try:
				if post[0] in sets and post[0] != "slowsearch":
					t = post[0]+" => "+sets.get(post[0])
					sets.pop(post[0])
					var.remove(t)
					print "Removed Values For \"%s\"" %data
			except Exception as e:
				pass
		elif cmd == "read" and len(post) > 0:
			if len(post[0]) > 0:
				post[0] = fdir(post[0])
				if os.path.isfile(post[0]):
					print open(post[0]).read()
					print
				else:
					sys.stderr.write(" => Invalid file path\n")
		elif cmd == "install" and len(post) > 0:
			if post[0] == "exploitdb":
				db = "https://github.com/offensive-security/exploit-database/archive/master.zip"
				resp = urllib.urlopen(db)
				try:
					file_size = int(resp.info().getheaders("Content-Length")[0])
				except AttributeError:
					file_size = int(resp.info().get("Content-Length"))
				downloaded_size = 0
				block_size = 4096
				sys.stderr.write("[*] ")
				sys.stdout.write("Downloading exploit-db\n")
				with open("./master.zip", "wb") as outfile:
					buff = resp.read(block_size)
					while buff:
						outfile.write(buff)
						downloaded_size += len(buff)
						downloaded_part = float(downloaded_size) / file_size
						progress_size = int(downloaded_part * 39)
						status = "[{0}{1}] {2:.2%}".format(
						"#" * progress_size,
						" " * (39 - progress_size), downloaded_part)
						sys.stdout.write("\r"+status+'\b' * (len(status) + 1))
						buff = resp.read(block_size)
					print
				sys.stderr.write("[*] ")
				sys.stdout.write("Unpackaging files (inturrupt process if it takes over 5 minutes)")
				try:
					zip_ref = zipfile.ZipFile("master.zip", "r")
					if raw_input(" => Run unzipping in background? [Y/n]\n    =>").lower() == "y":
						threading.Thread(target=zip_ref.extractall, args=("./",)).start()
					else:
						zip_ref.extractall("./")
						zip_ref.close()
				except:
					pass
				if os.path.isdir("./exploit-database-master"):
					if os.path.isdir("./exploits"):
						os.remove("./exploits")
					shutil.move("./exploit-database-master/exploits","./exploits")
					shutil.rmtree("./exploit-database-master/")
					if os.path.isfile("master.zip"):
						os.remove("master.zip")
					sys.stderr.write("[*] ")
					sys.stdout.write("Unpackaging process complete! Files have been added to your database!\n")
				else:
					sys.stderr.write("[!] ")
					sys.stdout.write("Unpackaging process interrupt too earily\n")
		elif cmd == "uninstall" and len(post) > 0:
			if len(post[0]) > 0:
				if post[0] == "notpy" or post[0] == "nonpy":
					end = "non python"
				else:
					end = ".%s"%post[0]
				sys.stderr.write("[!] ")
				sys.stdout.write("Are you sure you wish to uninstall all %s files? [Y/n]\n    => "%end)
				if raw_input().lower() == "y":
					if post[0] == "notpy":
						for prg in fdir("", get=True, end=""):
							ldir = ""
							if ".py" not in prg:
								ndir = "/".join(prg.split("/")[:-1])[2:]
								if ldir != ndir:
									sys.stdout.write(("\r[*] Cleaning: %s"+(" "*15))%ndir)
									ldir = ndir
								if sets["slowsearch"] == "true":
									time.sleep(0.005)
								if "exploit" in prg or "payload" in prg or "auxiliary" in prg:
									os.remove(prg)
					else:
						for prg in fdir("", get=True, end=end):
							ldir = ""
							if "."+post[0] in prg:
								ndir = "/".join(prg.split("/")[:-1])[2:]
								if ldir != ndir:
									sys.stdout.write(("\r[*] Cleaning: %s"+(" "*15))%ndir)
									ldir = ndir
								if sets["slowsearch"] == "true":
									time.sleep(0.005)
								os.remove(prg)
					clean_folders()
					print "\n"
		extended_cmd(cmd, post, loc)

if __name__ == "__main__":
	try:
		if int(os.uname()[-1][6]) >= 7:
			globals()["size"] = 12
		else:
			globals()["size"] = 9.5
	except:
		pass
	t = threading.Thread(target=collectprograms)
	t.name = "information_process_mbs"
	t.daemon = True
	t.start()
	mobilesplot_startup()
	if os.path.isdir("./exploit-database-master"):
		if os.path.isdir("./exploits"):
			shutil.rmtree("./exploits")
		shutil.move("./exploit-database-master/exploits","./exploits")
		shutil.rmtree("./exploit-database-master/")
		if os.path.isfile("master.zip"):
			os.remove("master.zip")
	while 1:
		commandline()
