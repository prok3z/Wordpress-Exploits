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
import urllib 

class wpsql:
	check = wphttp.check()
	printf = wpprint.wpprint()
	def __init__(self,agent,proxy,redirect,url,method,payload):
		self.url = url 
		self.method = method 
		self.payload = payload
		self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

	def dberror(self,data):
		if re.search("You have an error in your SQL syntax",data):
			return "MySQL Injection"
		if re.search("supplied argument is not a valid MySQL",data):
			return "MySQL Injection"
		if re.search("Microsoft ODBC Microsoft Access Driver",data):
			return "Access-Based SQL Injection"
		if re.search('Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error',data):
			return "MSSQL-Based Injection"
		if re.search("Microsoft OLE DB Provider for ODBC Drivers",data):
			return "MSSQL-Based Injection"
		if re.search("java.sql.SQLException: Syntax error or access violation",data):
			return "Java.SQL Injection"
		if re.search("PostgreSQL query failed: ERROR: parser:",data):
			return "PostgreSQL Injection"
		if re.search("XPathException",data):
			return "XPath Injection"
		if re.search("supplied argument is not a valid ldap",data) or re.search("javax.naming.NameNotFoundException",data):
			return "LDAP Injection"
		if re.search("DB2 SQL error",data):
			return "DB2 Injection"
		if re.search("Dynamic SQL Error",data):
			return "Interbase Injection"
		if re.search("Sybase message:",data):
			return "Sybase Injection"
		oracle = re.search('ORA-[0-9]',data)
		if oracle != None:
			return "Oracle Injection"+" "+oracle.group(0)
		return ""

	def run(self):
		self.printf.test("Testing SQL vulns...")
		print ""
		params = dict([x.split("=") for x in self.payload.split("&")])
		param = {}
		db = open("data/wpsql.txt","rb")
		file = [x.split("\n") for x in db]
		try:
			for item in params.items():
				for x in file:
					param[item[0]]=item[1].replace(item[1],x[0])
					enparam = urllib.urlencode(param)
					url = self.check.checkurl(self.url,"")
					resp = self.req.send(url,self.method,enparam)
					data = self.dberror(resp.read())
					if data != "":
						self.printf.erro("[%s][%s][%s] %s"%(resp.getcode(),self.method,data,resp.geturl()))
					else:
						self.printf.plus("[%s][%s][not vuln] %s"%(resp.getcode(),self.method,resp.geturl()))
					param[item[0]] = item[1].replace(x[0],item[1])
		except Exception as error:
			pass