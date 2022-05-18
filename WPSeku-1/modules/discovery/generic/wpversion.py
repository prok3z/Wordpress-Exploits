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

class wpversion:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url 
		self.req = wphttp.wphttp(agent=agent,redirect=redirect,proxy=proxy)

	def run(self):
		self.printf.test('Checking wordpress version...')
		try:
			url = self.check.checkurl(self.url,'wp-links-opml.php')
			resp = self.req.send(url)
			vers = re.findall('\S+WordPress/(\d+.\d+[.\d+]*)',resp.read())
			if vers:
				self.printf.plus('Running WordPress version: %s'%(vers[0]))
				wpvuln().run(vers) 
		except Exception as error:
			print error
			try:
				url =self.check.checkurl(self.url,'feed')
				resp = self.req.send(url)
				vers = re.findall('\S+?v=(\d+.\d+[.\d+]*)',resp.read())
				if vers:
					self.printf.plus('Running WordPress version: %s'%(vers[0]))
					self.wpvuln().run(vers)
			except Exception as error:
				try:
					url = self.check.checkurl(self.url,'/feed/atom')
					resp = self.req.send(url)
					vers = re.findall('<generator uri="http://wordpress.org/" version="(\d+\.\d+[\.\d+]*)"',resp.read())
					if vers:
						self.printf.plus('Running WordPress version: %s'%(vers[0]))
						self.wpvuln().run(vers)
				except Exception as error:
					try:
						url = self.check.checkurl(self.url,'/feed/rdf')
						resp = self.req.send(url)
						vers = re.findall('\S+?v=(\d+.\d+[.\d+]*)',resp.read())
						if vers:
							self.printf.plus('Running WordPress version: %s'%(vers[0]))
							self.wpvuln().run(vers)
					except Exception as error:
						try:
							url = self.check.checkurl(self.url,'/comments/feed')
							resp = self.req.send(url)
							vers = re.findall('\S+?v=(\d+.\d+[.\d+]*)',resp.read())
							if vers:
								self.printf.plus('Running WordPress version: %s'%(vers[0]))
								self.wpvuln().run(vers)
						except Exception as error:
							try:
								url = self.check.checkurl(self.url,'readme.html')
								resp = self.req.send(url)
								vers = re.findall('.*wordpress-logo.png" /></a>\n.*<br />.* (\d+\.\d+[\.\d+]*)\n</h1>',resp.read())
								if vers:
									self.printf.plus('Running WordPress version: %s'%(vers[0]))
									self.wpvuln().run(vers)
							except Exception as error:
								try:
									url = self.check.checkurl(self.url,'')
									resp = self.req.send(url)
									vers = re.findall('<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)"',resp.read())
									if vers:
										self.printf.plus('Running WordPress version: %s'%(vers[0]))
										self.wpvuln().run(vers)
								except Exception as error:
									self.printf.erro('Not found running WordPress version')
class wpvuln:
	printf = wpprint.wpprint()
	def run(self,version):
		try:
			v1,v2,v3 = [x.split('.') for x in version][0]
			self.vers = v1+v2+v3
		except ValueError:
			try:
				v1,v2 = [x.split('.') for x in version][0]
				self.vers = v1+v2
			except ValueError:
				self.vers = version[0]
		try:
			req = requests.packages.urllib3.disable_warnings()
			req = requests.get("https://wpvulndb.com/api/v2/wordpresses/"+self.vers,headers={'User-agent':'Mozilla/5.0'},verify=False)
			j = json.loads(req.content)
			print ""
			if j[version[0]]["vulnerabilities"]:
				for x in range(len(j[version[0]]["vulnerabilities"])):
					self.printf.ipri("Title: %s"%(j[version[0]]["vulnerabilities"][x]["title"]),color="r")
					if j[version[0]]["vulnerabilities"][x]["references"]:
						for z in range(len(j[version[0]]["vulnerabilities"][x]["references"]["url"])):
							self.printf.ipri("Reference: %s"%(j[version[0]]["vulnerabilities"][x]["references"]["url"][z]),color="g")
					self.printf.ipri("Fixed in: %s"%(j[version[0]]["vulnerabilities"][x]["fixed_in"]),color="g")
					print ""
			else:
				self.printf.ipri('Not found vulnerabilities',color="g")
				print ""
		except Exception as error:
			pass