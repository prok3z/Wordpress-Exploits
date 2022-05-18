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
import json
import requests
import wpstyle
import wpreadme
import wplisting
import wplicense
import wpfpd
import wpchangelog

class wptheme:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url 
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wpch = wpchangelog.wpchangelog(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wpfpd = wpfpd.wpfpd(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wpli = wplicense.wplicense(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wplis = wplisting.wplisting(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wprea = wpreadme.wpreadme(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wpst = wpstyle.wpstyle(agent=agent,proxy=proxy,redirect=redirect,url=url)

	def run(self):
		self.printf.test('Enumeration themes...')
		try:
			url = self.check.checkurl(self.url,'')
			resp = self.req.send(url)
			theme = re.findall('/wp-content/themes/(.+?)/',resp.read())
			new = []
			for i in theme:
				if i not in new:
					new.append(i)
			if new != []:
				for c in range(len(new)):
					print ""
					self.printf.ipri('Name: %s'%(new[c]),color="g")
					self.info(new[c])
					self.wpst.run(new[c])
					self.wpch.run(new[c])
					self.wpfpd.run(new[c])
					self.wpli.run(new[c])
					self.wplis.run(new[c])
					self.wprea.run(new[c])
					wpvuln().run(new[c])
				print ""
			else:
				self.printf.ipri('Not found themes',color="g")
		except Exception as error:
			pass
	
	def info(self,theme):
		try:
			url = self.check.checkurl(self.url,"/wp-content/themes/%s/%s"%(theme,"style.css"))
			resp = self.req.send(url)
			html = resp.read()
			self.printf.ipri('Theme Name: %s'%(re.findall("Theme Name: (\w+)",html)[0]),color="g")
			self.printf.ipri('Theme URL: %s'%(re.findall("Theme URI: (\S+)",html)[0]),color="g")
			self.printf.ipri('Author: %s'%(re.findall("Author: (\S+)",html)[0]),color="g")
			self.printf.ipri('Author URL: %s'%(re.findall("Author URI: (\S+)",html)[0]),color="g")
			self.printf.ipri('Version: %s'%(re.findall("Version: (\d+.\d+[.\d+]*)",html)[0]),color="g")
		except Exception as error:
			pass

class wpvuln:
	printf = wpprint.wpprint()
	def run(self,theme):
		try:
			req = requests.packages.urllib3.disable_warnings()
			req = requests.get("https://www.wpvulndb.com/api/v2/themes/"+theme,headers={'User-agent':'Mozilla/5.0'},verify=False)
			j = json.loads(req.content)
			if j[theme]:
				if j[theme]["vulnerabilities"]:
					for x in range(len(j[theme]["vulnerabilities"])):
						print ""
						self.printf.ipri('Title: %s'%(j[theme]["vulnerabilities"][x]['title']),color="r")
						if j[theme]["vulnerabilities"][x]["references"]["url"]:
							for z in range(len(j[theme]["vulnerabilities"][x]["references"]["url"])):
								self.printf.ipri('Reference: %s'%(j[theme]["vulnerabilities"][x]["references"]["url"][z]),color="g")
						self.printf.ipri('Fixed in: %s'%(j[theme]["vulnerabilities"][x]["fixed_in"]),color="g")
				else:
					self.printf.ipri('Not found vulnerabilities',color="g")
			else:
				self.printf.ipri('Not found vulnerabilities',color="g")
		except Exception as error:
			self.printf.ipri('Not found vulnerabilities',color="g")