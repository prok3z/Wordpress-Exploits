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
import urllib 

class wpxss:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url,method,payload):
		self.url = url 
		self.method = method	
		self.payload = payload
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def run(self):
		self.printf.test("Testing XSS vulns...")
		print ""
		params = dict([x.split("=") for x in self.payload.split("&")])
		param = {}
		db = open("data/wpxss.txt","rb")
		file = [x.split("\n") for x in db]
		try:
			for item in params.items():
				for x in file:
					param[item[0]]=item[1].replace(item[1],x[0])
					enparam = urllib.urlencode(param)
					url = self.check.checkurl(self.url,"")
					resp = self.req.send(url,self.method,enparam)
					if re.search(x[0],resp.read()) and resp.getcode() == 200:
						self.printf.erro("[%s][%s][vuln] %s"%(resp.getcode(),self.method,resp.geturl()))
					else:
						self.printf.plus("[%s][%s][not vuln] %s"%(resp.getcode(),self.method,resp.geturl()))
		except Exception as error:
			pass
