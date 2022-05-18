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

class wplisting:
    check = wphttp.check()
    printf = wpprint.wpprint()
    def __init__(self,agent,proxy,redirect,url):
        self.url = url
        self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

    def run(self):
        self.printf.test('Checking dir listing...')
        dir = ['/wp-admin','/wp-includes','/wp-content/uploads','/wp-content/plugins','/wp-content/themes']
        for i in dir:
            try:
                url = self.check.checkurl(self.url,i)
                resp = self.req.send(url)
                html = resp.read()
                if html and resp.getcode() == 200:
                    if re.search('Index of',html):
                        self.printf.plus('dir %s listing enabled under: %s'%(i,url))
                    else:
                        self.printf.erro('dir %s not listing enabled'%(i))
                else:
                    self.printf.erro('dir %s not listing enabled'%(i))
            except Exception as error:
                pass
