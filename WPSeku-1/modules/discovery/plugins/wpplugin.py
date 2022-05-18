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
import wpchangelog
import wplicense
import wplisting
import wpreadme

class wpplugin:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url 
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wpchangelog = wpchangelog.wpchangelog(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wplicense = wplicense.wplicense(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wplisting = wplisting.wplisting(agent=agent,proxy=proxy,redirect=redirect,url=url)
		self.wpreadme = wpreadme.wpreadme(agent=agent,proxy=proxy,redirect=redirect,url=url)

	def run(self):
		self.printf.test('Enumeration plugins...')
		try:
			url = self.check.checkurl(self.url,'')
			resp = self.req.send(url)
			plugin = re.findall('/wp-content/plugins/(.+?)/',resp.read())
			new = []
			for i in plugin:
				if i not in new:
					new.append(i)
			if new != []:
				for c in range(len(new)):
					print ""
					self.printf.ipri('Name: %s - %s'%(new[c],self.version(new[c])),color="g")
					self.wpchangelog.run(new[c])
					self.wplicense.run(new[c])
					self.wplisting.run(new[c])
					self.wpreadme.run(new[c])
					wpvuln().run(new[c])
				print ""
			else:
				self.printf.ipri('Not found plugins')
		except Exception as error:
			pass

	def version(self,plugin):
		try:
			url = self.check.checkurl(self.url,'')
			resp = self.req.send(url)
			ver = re.findall('/wp-content/plugins/%s\S+?ver=(\d+.\d+[.\d+]*)'%(plugin),resp.read())
			if len(ver) >= 2:
				return ver[0]
			elif len(ver) == 1:
				return ver[0]
			else:
				return None
		except Exception as error:
			pass

class wpvuln:
	printf = wpprint.wpprint()
	def run(self,plugin):
		try:
			req = requests.packages.urllib3.disable_warnings()
			req = requests.get("https://www.wpvulndb.com/api/v2/plugins/"+plugin,headers={'User-agent':'Mozilla/5.0'},verify=False)
			j = json.loads(req.content,"utf-8")
			if j[plugin]:
				if j[plugin]["vulnerabilities"]:
					for x in range(len(j[plugin]["vulnerabilities"])):
						print ""
						self.printf.ipri('Title: %s'%(j[plugin]["vulnerabilities"][x]['title']),color="r")
						if j[plugin]["vulnerabilities"][x]["references"]["url"]:
							for z in range(len(j[plugin]["vulnerabilities"][x]["references"]["url"])):
								self.printf.ipri('Reference: %s'%(j[plugin]["vulnerabilities"][x]["references"]["url"][z]),color="g")
						self.printf.ipri('Fixed in: %s'%(j[plugin]["vulnerabilities"][x]["fixed_in"]),color="g")
				else:
					self.printf.ipri('Not found vulnerabilities',color="g")
			else:
				self.printf.ipri('Not found vulnerabilities',color="g")
		except Exception as error:
			self.printf.ipri('Not found vulnerabilities',color="g")