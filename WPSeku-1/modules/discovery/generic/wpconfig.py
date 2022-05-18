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

class wpconfig:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def run(self):
		self.printf.test('Checking wp-config...')
		try:
			url = self.check.checkurl(self.url,'/wp-config.php')
			resp = self.req.send(url)
			html = resp.read()
			if html and resp.getcode() == 200:
				if re.search('\S+define(\S+,*)',html):
					self.printf.plus('wp-config available under: %s'%(url))
				else:
					self.printf.erro('wp-config not available')
			else:
				self.printf.erro('wp-config not available')
			self.wpconfigsample()
			self.backup()
		except Exception as error:
			pass

	def backup(self):
		self.printf.test('Checking wp-config backup...')
		ext = ['.php~','.backup','.bck','.old','.save','.bak','.copy','.tmp','.txt',
		'.zip','.db','.dat','.tar.gz','.back','.test','.temp','.orig']
		for x in ext:
			try:
				url = self.check.checkurl(self.url,'/wp-config'+x)
				resp = self.req.send(url)
				if resp.read() and resp.getcode() == 200:
					self.printf.plus('wp-config backup available under: %s'%(url))
				else:
					self.printf.erro('wp-config%s backup not available'%x)
			except Exception as error:
				pass

	def wpconfigsample(self):
		self.printf.test('Checking wp-config-sample...')
		try:
			url = self.check.checkurl(self.url,'wp-config-sample.php')
			resp = self.req.send(url)
			if resp.read() and resp.getcode() == 500:
				self.printf.plus('wp-config-sample available under: %s'%(url))
			else:
				self.printf.erro('wp-config-sample not available')
		except Exception as error:
			pass



