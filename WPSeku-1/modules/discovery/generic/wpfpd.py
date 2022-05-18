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

class wpfpd:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def run(self):
		self.printf.test('Checking Full Path Disclosure...')
		try:
			url = self.check.checkurl(self.url,'/wp-includes/rss-functions.php')
			resp = self.req.send(url)
			if re.search('Fatal error',resp.read()):
				self.printf.erro('Full Path Disclosure: %s'%(url))
			else:
				self.printf.erro('Full Path Disclosure not available')
		except Exception as error:
			pass
