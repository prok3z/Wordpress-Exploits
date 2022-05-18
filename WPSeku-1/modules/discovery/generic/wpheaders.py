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

class wpheaders:
    check = wphttp.check()
    printf = wpprint.wpprint()
    def __init__(self,agent,proxy,redirect,url):
        self.url = url
        self.req = wphttp.wphttp(agent=agent,proxy=proxy,redirect=redirect)

    def run(self):
        self.printf.test("Interesting headers...")
        print ""
        try:
    		url = self.check.checkurl(self.url,'')
    		r = self.req.send(url)
    		if r.info().getheader('accept-charset'):
    			print 'Accept-Charset: %s'%(r.info().getheader('accept-charset'))
    		if r.info().getheader('accept-encoding'):
    			print 'Accept-Encoding: %s'%(r.info().getheader('accept-encoding'))
    		if r.info().getheader('accept-language'):
    			print 'accept-language: %s'%(r.info().getheader('accept-language'))
    		if r.info().getheader('accept-ranges'):
    			print 'Accept-Ranges: %s'%(r.info().getheader('accept-ranges'))
    		if r.info().getheader('access-control-allow-credentials'):
    			print 'Access-Control-Allow-Credentials: %s'%(r.info().getheader('access-control-allow-credentials'))
    		if r.info().getheader('access-control-allow-headers'):
    			print 'Access-Control-Allow-Headers: %s'%(r.info().getheader('access-control-allow-headers'))
    		if r.info().getheader('access-control-allow-methods'):
    			print 'Access-Control-Allow-Methods: %s'%(r.info().getheader('access-control-allow-methods'))
    		if r.info().getheader('access-control-allow-origin'):
    			print 'Access-Control-Allow-Origin: %s'%(r.info().getheader('access-control-allow-origin'))
    		if r.info().getheader('access-control-expose-headers'):
    			print 'Access-Control-Expose-Headers: %s'%(r.info().getheader('access-control-expose-headers'))
    		if r.info().getheader('access-control-max-age'):
    			print 'Access-Control-Max-Age: %s'%(r.info().getheader('access-control-max-age'))
    		if r.info().getheader('age'):
    			print 'Age: %s'%(r.info().getheader('age'))
    		if r.info().getheader('allow'):
    			print 'Allow: %s'%(r.info().getheader('allow'))
    		if r.info().getheader('alternates'):
    			print 'Alternates: %s'%(r.info().getheader('alternates'))
    		if r.info().getheader('authorization'):
    			print 'Authorization: %s'%(r.info().getheader('authorization'))
    		if r.info().getheader('cache-control'):
    			print 'Cache-Control: %s'%(r.info().getheader('cache-control'))
    		if r.info().getheader('connection'):
    			print 'Connection: %s'%(r.info().getheader('connection'))
    		if r.info().getheader('content-encoding'):
    			print 'Content-Encoding: %s'%(r.info().getheader('content-encoding'))
    		if r.info().getheader('content-language'):
    			print 'Content-Language: %s'%(r.info().getheader('content-language'))
    		if r.info().getheader('content-length'):
    			print 'Content-Length: %s'%(r.info().getheader('content-length'))
    		if r.info().getheader('content-location'):
    			print 'Content-Location: %s'%(r.info().getheader('content-location'))
    		if r.info().getheader('content-md5'):
    			print 'Content-md5: %s'%(r.info().getheader('content-md5'))
    		if r.info().getheader('content-range'):
    			print 'Content-Range: %s'%(r.info().getheader('content-range'))
    		if r.info().getheader('content-security-policy'):
    			print 'Content-Security-Policy: %s'%(r.info ().getheader('content-security-policy'))
    		if r.info().getheader('content-security-policy-report-only'):
    			print 'Content-Security-Policy-Report-Only: %s'%(r.info().getheader('content-security-policy-report-only'))
    		if r.info().getheader('content-type'):
    			print 'Content-Type: %s'%(r.info().getheader('content-type'))
    		if r.info().getheader('dasl'):
    			print 'Dasl: %s'%(r.info().getheader('dasl'))
    		if r.info().getheader('date'):
    			print 'Date: %s'%(r.info().getheader('date'))
    		if r.info().getheader('dav'):
    			print 'Dav: %s'%r.info().getheader('dav')
    		if r.info().getheader('etag'):
    			print 'Etag: %s'%(r.info().getheader('etag'))
    		if r.info().getheader('from'):
    			print 'From: %s'%(r.info().getheader('from'))
    		if r.info().getheader('host'):
    			print 'Host: %s'%(r.info().getheader('host'))
    		if r.info().getheader('keep-alive'):
    			print 'Keep-Alive: %s'%(r.info().getheader('keep-alive'))
    		if r.info().getheader('last-modified'):
    			print 'Last-Modified: %s'%(r.info().getheader('last-modified'))
    		if r.info().getheader('location'):
    			print 'Location: %s'%(r.info().getheader('location'))
    		if r.info().getheader('max-forwards'):
    			print 'Max-Forwards: %s'%(r.info().getheader('max-forwards'))
    		if r.info().getheader('persistent-auth'):
    			print 'Persistent-Auth: %s'%(r.info().getheader('persistent-auth'))
    		if r.info().getheader('pragma'):
    			print 'Pragma: %s'%(r.info().getheader('pragma'))
    		if r.info().getheader('proxy-authenticate'):
    			print 'Proxy-Authenticate: %s'%(r.info().getheader('proxy-authenticate'))
    		if r.info().getheader('proxy-authorization'):
    			print 'Proxy-Authorization: %s'%(r.info().getheader('proxy-authorization'))
    		if r.info().getheader('proxy-connection'):
    			print 'Proxy-Connection: %s'%(r.info().getheader('proxy-connection'))
    		if r.info().getheader('public'):
    			print 'Public: %s'%(r.info().getheader('public'))
    		if r.info().getheader('range'):
    			print 'Range: %s'%(r.info().getheader('range'))
    		if r.info().getheader('referer'):
    			print 'Referer: %s'%(r.info().getheader('referer'))
    		if r.info().getheader('server'):
    			print 'Server: %s'%(r.info().getheader('server'))
    		if r.info().getheader('set-cookie'):
    			print 'Set-Cookie: %s'%(r.info().getheader('set-cookie'))
    		if r.info().getheader('status'):
    			print 'Status: %s'%(r.info().getheader('status'))
    		if r.info().getheader('strict-transport-security'):
    			print 'Strict-Transport-Security: %s'%(r.info().getheader('strict-transport-security'))
    		if r.info().getheader('transfer-encoding'):
    			print 'Transfer-Encoding: %s'%(r.info().getheader('transfer-encoding'))
    		if r.info().getheader('upgrade'):
    			print 'Upgrade: %s'%(r.info().getheader('upgrade'))
    		if r.info().getheader('vary'):
    			print 'Vary: %s'%(r.info().getheader('vary'))
    		if r.info().getheader('via'):
    			print 'Via: %s'%(r.info().getheader('via'))
    		if r.info().getheader('warning'):
    			print 'Warning: %s'%(r.info().getheader('warning'))
    		if r.info().getheader('www-authenticate'):
    			print 'www-Authenticate: %s'%(r.info().getheader('www-authenticate'))
    		if r.info().getheader('x-content-security-policy'):
    			print 'X-Content-Security-Policy: %s'%(r.info().getheader('x-content-security-policy'))
    		if r.info().getheader('x-content-type-options'):
    			print 'X-Content-Type-Options: %s'%(r.info().getheader('x-content-type-options'))
    		if r.info().getheader('x-frame-options'):
    			print 'X-Frame-Options: %s'%(r.info().getheader('x-frame-options'))
    		if r.info().getheader('x-id'):
    			print 'X-Id: %s'%(r.info().getheader('x-id'))
    		if r.info().getheader('x-mod-pagespeed'):
    			print 'X-Mod-Pagespeed: %s'%(r.info().getheader('x-mod-pagespeed'))
    		if r.info().getheader('x-pad'):
    			print 'X-Pad: %s'%(r.info().getheader('x-pad'))
    		if r.info().getheader('x-page-speed'):
    			print 'X-Page-Speed: %s'%(r.info().getheader('x-page-speed'))
    		if r.info().getheader('x-permitted-cross-domain-policies'):
    			print 'X-Permitted-Cross-Domain-Policies: %s'%(r.info().getheader('x-permitted-cross-domain-policies'))
    		if r.info().getheader('x-pingback'):
    			print 'X-Pingback: %s'%(r.info().getheader('x-pingback'))
    		if r.info().getheader('x-powered-by'):
    			print 'X-Powered-By: %s'%(r.info().getheader('x-powered-by'))
    		if r.info().getheader('x-robots-tag'):
    			print 'X-Robots-Tag: %s'%(r.info().getheader('x-robots-tag'))
    		if r.info().getheader('x-ua-compatible'):
    			print 'X-UA-Compatible: %s'%(r.info().getheader('x-ua-compatible'))
    		if r.info().getheader('x-varnish'):
    			print 'X-Varnish: %s'%(r.info().getheader('x-varnish'))
    		if r.info().getheader('x-xss-protection'):
    			print 'X-XSS-Protection: %s'%(r.info().getheader('x-xss-protection'))
    	except Exception as error:
    		pass
        print ""