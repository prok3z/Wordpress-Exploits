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

import wpconfig
import wpcrossdomain
import wpheaders
import wphtaccess
import wplicense
import wplisting
import wpreadme
import wprobots
import wpsitemap
import wpversion 
import wpxmlrpc
import wpfpd
import wpwaf
import wploginprotection as wplp

class wpgeneric:
	def run(self,agent,proxy,redirect,url):
		wpsitemap.wpsitemap(agent,proxy,redirect,url).run()
		wplicense.wplicense(agent,proxy,redirect,url).run()
		wprobots.wprobots(agent,proxy,redirect,url).run()
		wpcrossdomain.wpcrossdomain(agent,proxy,redirect,url).run()
		wpreadme.wpreadme(agent,proxy,redirect,url).run()
		wphtaccess.wphtaccess(agent,proxy,redirect,url).run()
		wpxmlrpc.wpxmlrpc(agent,proxy,redirect,url).run()
		wpfpd.wpfpd(agent,proxy,redirect,url).run()
		wpconfig.wpconfig(agent,proxy,redirect,url).run()
		wplisting.wplisting(agent,proxy,redirect,url).run()
		wpheaders.wpheaders(agent,proxy,redirect,url).run()
		wpwaf.wpwaf(agent,proxy,redirect,url).run()
		wplp.wploginprotection(agent,proxy,redirect,url).run()
		wpversion.wpversion(agent,proxy,redirect,url).run()