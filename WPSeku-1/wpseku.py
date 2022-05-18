#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)
#
# WPSeku is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 3 of the License.
#
# WPSeku is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WPSeku; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
# Add path to seft.target


from lib import wpcolor
from lib import wphttp
from lib import wpprint
import os
import sys
import getopt
import time
import urlparse
from modules.discovery import wpall
from modules.bruteforce import wpxmlrpc
from modules.attack import wpxss
from modules.attack import wpsql
from modules.attack import wplfi

class WPSeku(object):
	"""docstring for WPSeku"""
	r =  wpcolor.wpcolor().red(1)
	w = wpcolor.wpcolor().white(0)
	y = wpcolor.wpcolor().yellow(4)
	e = wpcolor.wpcolor().reset()
	xss = False
	sql = False
	lfi = False
	brute = False
	agent = ""
	proxy = None
	redirect = True
	cookie = None
	user = None
	method = None
	query = None
	wordlist = None  
	check = wphttp.check()
	printf = wpprint.wpprint()
	_ = wpall.wpall()	
	def __init__(self, kwargs):
		self.kwargs = kwargs

	def Banner(self):
		print self.r+r"__        ______  ____       _          "+self.e
		print self.r+r"\ \      / /  _ \/ ___|  ___| | ___   _ "+self.e
		print self.r+r" \ \ /\ / /| |_) \___ \ / _ \ |/ / | | |"+self.e
		print self.r+r"  \ V  V / |  __/ ___) |  __/   <| |_| |"+self.e
		print self.r+r"   \_/\_/  |_|   |____/ \___|_|\_\\__,_|"+self.e
		print self.w+"                                         "+self.e
		print self.w+"|| WPSeku - Wordpress Security Scanner   "+self.e
		print self.w+"|| Version 0.2.1                         "+self.e
		print self.w+"|| Momo Outaadi (M4ll0k)                 "+self.e
		print self.w+"|| %shttps://github.com/m4ll0k/WPSeku%s\n"%(self.y,self.e)

	def Usage(self,ext=False):
		path = os.path.basename(sys.argv[0])
		self.Banner()
		print "Usage: ./%s [--target|-t] http://localhost\n"%path
		print "\t-t --target\tTarget URL (eg: http://localhost)"
		print "\t-x --xss\tTesting XSS vulns"
		print "\t-s --sql\tTesting SQL vulns"
		print "\t-l --lfi\tTesting LFI vulns"
		print "\t-q --query\tTestable parameters (eg: \"id=1&test=1\")"
		print "\t-b --brute\tBruteforce login via xmlrpc"
		print "\t-u --user\tSet username, default=admin"
		print "\t-p --proxy\tSet proxy, (host:port)"
		print "\t-m --method\tSet method (GET/POST)"
		print "\t-c --cookie\tSet cookies"
		print "\t-w --wordlist\tSet wordlist"
		print "\t-a --agent\tSet user-agent"
		print "\t-r --redirect\tRedirect target url, default=True"
		print "\t-h --help\tShow this help and exit\n"
		print "Examples:"
		print "\t%s --target http://localhost"%path
		print "\t%s -t http://localhost/wp-admin/post.php -m GET -q \"post=49&action=edit\" [-x,-s,-l]"%path
		print "\t%s --target http://localhost --brute --wordlist dict.txt"%path
		print "\t%s --target http://localhost --brute --user test --wordlist dict.txt\n"%path
		if ext == True:
			sys.exit()

	def CheckTarget(self,url):
		scheme = urlparse.urlsplit(url).scheme
		netloc = urlparse.urlsplit(url).netloc
		path = urlparse.urlsplit(url).path
		if scheme not in ['http','https','']:
			sys.exit(self.printf.erro('Schme %s not supported'%(scheme)))
		if netloc == "":
			return "http://"+path
		else:
			return scheme+"://"+netloc+path

	def Main(self):
		if len(sys.argv) <= 2:
			self.Usage(True)
		try:
			opts,args = getopt.getopt(self.kwargs,"t:x=:s=:l=:b=:h=:q:u:p:m:c:w:a:r:",['target=','xss','sql','lfi','query=',
				'brute','user=','proxy=','method=','cookie=','wordlist=','agent=','redirect=','help'])
		except getopt.error as error:
			pass
		for o,a in opts:
			if o in ('-t','--target'):
				self.target = self.CheckTarget(a)
			if o in ('-x','--xss'):
				self.xss = True
			if o in ('-s','--sql'): 
				self.sql = True
			if o in ('-l','--lfi'):
				self.lfi = True
			if o in ('-q','--query'):
				self.query = a 
			if o in ('-b','--brute'):
				self.brute = True
			if o in ('-u','--user'):
				self.user = a 
			if o in ('-p','--proxy'):
				self.proxy = a 
			if o in ('-m','--method'):
				self.method = a 
			if o in ('-c','--cookie'):
				self.cookie = a 
			if o in ('-w','--wordlist'):
				self.wordlist = a 
			if o in ('-a','--agent'):
				self.agent = a 
			if o in ('-r','--redirect'):
				self.redirect = a 
			if o in ('-h','--help'):
				self.Usage(True)
		self.Banner()
		self.printf.plus('Target: %s'%self.target)
		self.printf.plus('Starting: %s\n'%(time.strftime('%d/%m/%Y %H:%M:%S')))
		print self.agent
		if not self.agent:self.agent = 'Mozilla/5.0'
		if not self.proxy:self.proxy=None
		if not self.cookie:self.cookie=None
		if not self.redirect:self.redirect=False
		if not self.user:self.user="admin"
		# xss attack
		if self.xss==True:
			if not self.method:sys.exit(self.printf.erro('Method not exisits!'))
			if not self.query:sys.exit(self.printf.erro('Not found query'))
			wpxss.wpxss(self.agent,self.proxy,self.redirect,self.target,self.method,self.query).run()
			sys.exit()
		# sql attack
		if self.sql==True:
			if not self.method:sys.exit(self.printf.erro('Method not exisits!'))
			if not self.query:sys.exit(self.printf.erro('Not found query'))
			wpsql.wpsql(self.agent,self.proxy,self.redirect,self.target,self.method,self.query).run()
			sys.exit()
		# lfi attack
		if self.lfi==True:
			if not self.method:sys.exit(self.printf.erro('Method not exisits!'))
			if not self.query:sys.exit(self.printf.erro('Not found query'))
			wplfi.wplfi(self.agent,self.proxy,self.redirect,self.target,self.method,self.query).run()
			sys.exit()
		# attack bruteforce
		if self.brute==True:
			if not self.wordlist:sys.exit(self.printf.erro('Not found wordlist!'))
			wpxmlrpc.wpxmlrpc(self.agent,self.proxy,self.redirect,self.target,self.cookie,self.wordlist,self.user).run()
			sys.exit()
		# discovery
		if self.target:
			self._.run(self.agent,self.proxy,self.redirect,self.target)

if __name__ == "__main__":
	try:
		WPSeku(sys.argv[1:]).Main()
	except KeyboardInterrupt as error:
		sys.exit("[!] Keyboard Interrupt by User")
