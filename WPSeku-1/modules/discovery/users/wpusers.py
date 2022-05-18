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

class wpusers:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url 
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def run(self):
		self.printf.test("Enumeration usernames...")
		l = []
		for x in range(0,15):
			try:
				url = self.check.checkurl(self.url,'/?author=%s'%x)
				resp = self.req.send(url)
				if resp.getcode() == 200:
					html = resp.read()
					login = re.findall('/author/(.+?)/',html)
					l.append(login)
			except Exception as error:
				print error
		login_new = []
		for i in l:
			if i not in login_new:
				login_new.append(i)
		##################
		try:
			if login_new != []:
				for a in range(len(login_new)):
					if "%20" in login_new[a][0]:
						self.printf.ipri(" ID: %s   |  Login: %s"%(a,login_new[a][0].replace('%20',' ')),color="g")
					else:
						self.printf.ipri(" ID: %s  |  Login: %s"%(a,login_new[a][0]),color="g")
				print ""
			if login_new == []:
				self.printf.ipri("Not found usernames",color="r")
		except Exception as error:
			self.printf.ipri("Not found usernames",color="r")