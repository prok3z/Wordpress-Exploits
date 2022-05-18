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
from generic import wpgeneric 
from plugins import wpplugin
from themes import wptheme
from users import wpusers 

class wpall:
	def run(self,agent,proxy,redirect,url):
		wpgeneric.wpgeneric().run(agent,proxy,redirect,url)
		wptheme.wptheme(agent,proxy,redirect,url).run()
		wpplugin.wpplugin(agent,proxy,redirect,url).run()
		wpusers.wpusers(agent,proxy,redirect,url).run()