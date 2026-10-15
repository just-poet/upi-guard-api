"""Bounded public-page reader. Pins validated DNS addresses for every redirect hop."""
import asyncio
import http.client
import ipaddress
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

MAX_BYTES = 120000
MAX_TEXT = 10000


class PageText(HTMLParser):
    def __init__(self):
        super().__init__(); self.skip=0; self.parts=[]; self.title=[]; self.in_title=False
    def handle_starttag(self, tag, attrs):
        if tag in ('script','style','noscript','svg'): self.skip+=1
        if tag=='title': self.in_title=True
    def handle_endtag(self, tag):
        if tag in ('script','style','noscript','svg') and self.skip: self.skip-=1
        if tag=='title': self.in_title=False
    def handle_data(self, data):
        if not self.skip:
            value=' '.join(data.split())
            if value:
                self.parts.append(value)
                if self.in_title: self.title.append(value)


def public_target(raw):
    if len(raw)>2048 or any(ord(c)<33 or c=='\\' for c in raw):
        raise ValueError('The URL is malformed.')
    try:
        u=urlsplit(raw)
        host=(u.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
        port=u.port or (443 if u.scheme.lower()=='https' else 80)
    except (ValueError,UnicodeError):
        raise ValueError('The URL is malformed.') from None
    if u.scheme.lower() not in ('http','https') or not host or u.username or u.password or port not in (80,443):
        raise ValueError('Only public HTTP/HTTPS links without credentials on ports 80/443 can be inspected.')
    if host=='localhost' or host.endswith(('.localhost','.local','.internal','.lan','.home','.test','.invalid')) or '.' not in host and ':' not in host:
        raise ValueError('Local and internal addresses cannot be inspected.')
    try:
        address=ipaddress.ip_address(host)
        if not address.is_global or address.is_multicast or address.is_unspecified:
            raise ValueError('Private, reserved and local addresses cannot be inspected.')
    except ValueError as error:
        if ':' in host or re.fullmatch(r'[0-9.]+',host): raise ValueError('Non-public address cannot be inspected.') from error
    authority=f'[{host}]' if ':' in host else host
    if port!=(443 if u.scheme.lower()=='https' else 80): authority+=':'+str(port)
    path=quote(u.path or '/',safe="/%:@!$&'()*+,;=-._~")
    query=quote(u.query,safe="%=&?/:@!$'()*+,;~-._")
    return urlunsplit((u.scheme.lower(),authority,path,query,'')),host,port


def public_addresses(host,port):
    records=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
    addresses=list(dict.fromkeys(r[4][0] for r in records))
    if not addresses or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).is_multicast for ip in addresses):
        raise ValueError('The hostname resolves to a non-public address.')
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,ip,port,timeout):
        super().__init__(host,port=port,timeout=timeout,context=ssl.create_default_context());self.ip=ip
    def connect(self):
        sock=socket.create_connection((self.ip,self.port),self.timeout)
        try: self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
        except BaseException: sock.close();raise


def read_public_page(raw,deadline):
    original=raw; chain=[]
    try:
        for hop in range(4):
            url,host,port=public_target(raw)
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError
            ips=public_addresses(host,port)
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError
            parts=urlsplit(url)
            if parts.scheme=='https': conn=PinnedHTTPS(host,ips[0],port,remaining)
            else: conn=http.client.HTTPConnection(ips[0],port,timeout=remaining)
            try:
                conn.request('GET',urlunsplit(('','',parts.path,parts.query,'')),headers={'Host':parts.netloc,'User-Agent':'UPI-Guard-Link-Inspector/1.0','Accept':'text/html,text/plain,application/xhtml+xml','Accept-Encoding':'identity','Connection':'close'})
                response=conn.getresponse(); chain.append({'url':url,'http_status':response.status})
                if response.status in (301,302,303,307,308):
                    location=response.getheader('Location')
                    if not location or hop==3: raise ValueError('Too many redirects or a redirect without a destination.')
                    raw=urljoin(url,location);continue
                if response.status!=200:
                    return {'url':original,'final_url':url,'status':'unavailable','http_status':response.status,'redirects':chain,'reason':'The public page could not be read (it may require sign-in or block automated requests).'}
                content_type=response.getheader('Content-Type','').lower()
                if not any(t in content_type for t in ('text/html','text/plain','application/xhtml+xml')) or response.getheader('Content-Encoding','identity').lower() not in ('','identity'):
                    raise ValueError('This link does not return a supported uncompressed text/HTML page. No files were downloaded or executed.')
                data=bytearray()
                while len(data)<=MAX_BYTES:
                    remaining=deadline-time.monotonic()
                    if remaining<=0: raise TimeoutError
                    response_socket=conn.sock or getattr(getattr(getattr(response,'fp',None),'raw',None),'_sock',None)
                    if response_socket: response_socket.settimeout(remaining)
                    chunk=response.read1(min(4096,MAX_BYTES+1-len(data)))
                    if not chunk: break
                    data.extend(chunk)
                charset=re.search(r'charset=([\w-]+)',content_type)
                encoding=charset.group(1) if charset else 'utf-8'
                try: text=bytes(data[:MAX_BYTES]).decode(encoding,errors='replace')
                except LookupError: text=bytes(data[:MAX_BYTES]).decode('utf-8',errors='replace')
                title=''
                if 'html' in content_type:
                    parser=PageText();parser.feed(text);text=' '.join(parser.parts);title=' '.join(parser.title)[:250]
                return {'url':original,'final_url':url,'status':'fetched','http_status':200,'redirects':chain,'title':title,'text_excerpt':text[:MAX_TEXT],'truncated':len(data)>MAX_BYTES or len(text)>MAX_TEXT,'reason':'Read public text without cookies, sign-in, JavaScript execution, or file downloads.'}
            finally: conn.close()
    except ValueError as error:
        return {'url':original,'status':'blocked','redirects':chain,'reason':str(error)}
    except (OSError,http.client.HTTPException,TimeoutError):
        return {'url':original,'status':'unavailable','redirects':chain,'reason':'The public page could not be read within the inspection time limit.'}


async def inspect_link(raw):
    try:
        return await asyncio.wait_for(asyncio.to_thread(read_public_page,raw,time.monotonic()+4.5),timeout=5.0)
    except asyncio.TimeoutError:
        return {'url':raw,'status':'unavailable','reason':'The public page did not respond within the inspection time limit.'}
