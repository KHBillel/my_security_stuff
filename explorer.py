from bs4 import BeautifulSoup
import mechanize
from pprint import pprint
from urllib.parse import urljoin


class explorer(object) :
    def __init__(self):
        self.target = None
        self.uses_https = False
        self.max_depth = 20
        self.br = mechanize.Browser()
        self.br.set_handle_robots(False)
        cj = mechanize.CookieJar()
        self.br.set_cookiejar(cj)
        self.discover = []
        self.mails =[]
        self.sitemap_graph = {}
        self.br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')] # A fake web browser
    
    def get_base_link(self, url) :
        rurl = ""
        chunks = url.split("/")
        if chunks[0] != "http:" and  chunks[0] != "https:" :
            if url[0] == '/' :
                return self.get_base_link(self.target)
            return url
        else :
            for i in range(2,len(chunks)-1) :
                rurl+=(chunks[i]+'/')

        return rurl

    def get_site_url(self, url) :
        chunks = url.split("/")
        if chunks[0] == "http:" or  chunks[0] == "https:" :
            return chunks[2]
        else :
            return chunks[0]

    def is_inner_link(self, url) :
        if not ('/' in url) or url[0] == '/' :
            return True
        else :
            if self.get_site_url(url) == self.get_site_url(self.target) :
                return True
            else :
                return False

    def prepare_link(self, url) :
        if url.split("/")[0] != "http:" and url.split("/")[0] != "https:" :
            return urljoin(self.br.geturl(), url)
        return url

    def is_mail(self, url) :
        return "mailto" in url

    def set_target(self, target) :
        self.target = target
        if "https://" in target :
            self.uses_https = True
        else :
            self.uses_https = False

    def set_max_depth(self, max_depth) :
        self.max_depth = max_depth

    def explore(self, target = None , d=0) :
        if d == self.max_depth :
            return
        pprint("Depth = "+str(d))
        if target == None :
            try:
                self.br.open(self.target)
            except :
                print("Crawler :( >> Can't open url: " + self.target)
                return
        else :
            if not(self.is_inner_link(target)) or (target in self.discover ) or ((target + "index.php") in self.discover ) or (target.replace("index.php", "") in self.discover):
                return

            try :
                self.br.open(target)
            except :
                print("Crawler :( >> Can't open url: " + target)
                return
        
        
        resp = self.br.response().read()
        soup = BeautifulSoup(resp, "lxml")
        links = soup.find_all("a")

        self.discover.append(self.br.geturl())

        was_in = self.br.geturl()
        self.sitemap_graph[was_in] = []

        for link in links :
            try :
                href = self.prepare_link(link.attrs["href"].split("#")[0].split("?")[0])
            except :
                continue
            
            if self.is_mail(href) :
                self.mails.append(href.split(":")[1])

            elif self.is_inner_link(href):
                self.sitemap_graph[was_in].append(href)
                self.explore(href, d+1)
                self.br.open(was_in)
    


if __name__ == "__main__" :
    e= explorer()
    e.set_target("http://127.0.0.1/projects/attack/Hackademic_Challenges/")
    e.explore()
    pprint(e.sitemap_graph)