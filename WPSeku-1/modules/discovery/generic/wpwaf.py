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

class wpwaf:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def run(self):
		self.printf.test('Checking WAF...')
		try:
			url = self.check.checkurl(self.url,"")
			resp = self.req.send(url)
			html = resp.read()
			if re.search('/wp-content/plugins/wordfence/',html):
				self.printf.plus('Firewall Detection: Wordfence Security')
			elif re.search('/wp-content/plugins/bulletproof-security/',html):
				self.printf.plus('Firewall Detection: BulletProof Security')
			elif re.search('/wp-content/plugins/sucuri-scanner/',html):
				self.printf.plus('Firewall Detection: Sucuri Security')
			elif re.search('/wp-content/plugins/better-wp-security/',html):
				self.printf.plus('Firewall Detection:  Better WP Security')
			elif re.search('/wp-content/plugins/wp-security-scan/',html):
				self.printf.plus('Firewall Detection: Acunetix WP SecurityScan')
			elif re.search('/wp-content/plugins/all-in-one-wp-security-and-firewall/',html):
				self.printf.plus('Firewall Detection: All In One WP Security & Firewall')
			elif re.search('/wp-content/plugins/6scan-protection',html):
				self.printf.plus('Firewall Detection: 6Scan Security')
			elif re.search('cloudflare-nginx',resp.info().getheader('server'),re.I):
				self.printf.plus('Firewall Detection: CloudFlare')
			elif re.search('__cfduid',resp.info().getheader('cookie'),re.I):
				self.printf.plus('Firewall Detection: CloudFlare')
			else:
				self.printf.erro('No Firewall Detected')
		except Exception as error:
			pass