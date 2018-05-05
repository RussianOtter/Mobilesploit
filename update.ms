# Version: "v2.5"
# Description: "Mobilesploit v3 Defaults"
# Packages: 2
# File: "packages.zip"

import os, sys, requests, time, random, zipfile, urllib, shutil

try:
	force
except:
	force = False

def extract_update(update):
	rate=0.0134
	try:
		zip_ref = zipfile.ZipFile(update, "r")
		zip_ref.extractall("./")
		zip_ref.close()
		os.remove("./temp.zip")
		os.remove("./packages.zip")
		pro = 0
		cn = 0
		lchr = u"\u2588"
		val = len(os.listdir("./packages"))
		for expfile in os.listdir("./packages"):
			a = int((cn/380.0)*100)
			pro += 1
			cn += 6
			p = 28-a
			msg = (lchr*a)+(" "*p)+" [%d/%d]  "
			sys.stdout.write("\r"+msg%(pro,val))
			time.sleep(rate)
			if expfile in os.listdir("./exploit"):
				u = open("./packages/"+expfile).read()
				f = open("./exploit/"+expfile,"w")
				f.write(u)
				f.close()
			else:
				shutil.move("packages/"+expfile,"./exploit")
		shutil.rmtree("./packages")
	except Exception as e:
		sys.stderr.write(" => %s\n"%str(e))
		sys.exit(1)

def download(filename="https://raw.githubusercontent.com/RussianOtter/Mobilesploit/master/packages.zip"):
	updater = urllib.FancyURLopener()
	updater.retrieve(filename, filename.split("/")[-1])

def mobileupdate(val="", v="", d="", install=""):
	lchr = u"\u2588"
	if raw_input(" => Mobilesploit Exploit Update Available!\n    => Update? [y/n] ").lower() == "y":
		print "Retrieving Mobilesploit Update..."
		download()
		time.sleep(0.8)
		print "Version:",v
		time.sleep(1)
		print "Description:",d
		time.sleep(1)
		print "Installing Packages..."
		time.sleep(1.5)
		extract_update(install)
		time.sleep(0.5)
		print " => Successfully Installed\n"

updateurl = "https://raw.githubusercontent.com/RussianOtter/Mobilesploit/master/update.ms"

for _ in "_":
	try:
		stat = open("./update.ms").read()
	except Exception as e:
		if "Mobilesploit.py" not in os.listdir("./"):
			download(updateurl)
			stat = open("update.ms").read()
		else:
			sys.stderr.write(" => %s\n"%str(e))
	
	try:
		update = requests.get(updateurl, timeout=5).text
	except Exception as e:
		sys.stderr.write(" => %s\n"%str(e))
		break
	
	if stat.split("\n")[0] != update.split("\n")[0] or force:
		packages = update.split("\n")[2].replace("# ","").replace(":","=")
		version = update.split("\n")[0].replace("# ","").replace(":","=")
		description = update.split("\n")[1].replace("# ","").replace(":","=")
		packagefile = update.split("\n")[3].replace("# ","").replace(":","=")
		exec packages
		exec version
		exec description
		exec packagefile
		mobileupdate(val=Packages, d=Description, v=Version, install=File)
