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

import wpcolor

class wpprint:

	r = wpcolor.wpcolor().red(1)
	nr = wpcolor.wpcolor().red(0)
	g = wpcolor.wpcolor().green(1)
	y = wpcolor.wpcolor().yellow(1)
	b = wpcolor.wpcolor().blue(1)
	w = wpcolor.wpcolor().white(1)
	nw = wpcolor.wpcolor().white(0)
	e = wpcolor.wpcolor().reset()

	def plus(self,string,flag="+"):
		print "%s[%s]%s %s%s%s"%(self.g,flag,self.e,self.nw,string,self.e)

	def test(self,string,flag="*"):
		print "%s[%s]%s %s%s%s"%(self.b,flag,self.e,self.nw,string,self.e)

	def warn(self,string,flag="!"):
		print "%s[%s]%s %s%s%s"%(self.nr,flag,self.e,self.nw,string,self.e)

	def erro(self,string,flag="-"):
		print "%s[%s]%s %s%s%s"%(self.r,flag,self.e,self.nw,string,self.e)

	def info(self,string,flag="i"):
		print "%s[%s]%s %s%s%s"%(self.y,flag,self.e,self.nw,string,self.e)

	def ipri(self,string,color=None,flag="|"):
		if color == "r":
			print " %s%s%s %s%s%s"%(self.r,flag,self.e,self.nw,string,self.e)
		if color == "g":
			print " %s%s%s %s%s%s"%(self.g,flag,self.e,self.nw,string,self.e)