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

class wpcolor:
	
	def red(self,num):
		return '\x1b['+str(num)+';31m'

	def green(self,num):
		return '\x1b['+str(num)+';32m'

	def yellow(self,num):
		return '\x1b['+str(num)+';33m'

	def blue(self,num):
		return '\x1b['+str(num)+';34m'

	def white(self,num):
		return '\x1b['+str(num)+';38m'

	def reset(self):
		return '\x1b[0m'
