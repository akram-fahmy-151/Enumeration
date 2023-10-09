import os
import argparse
import subprocess
import time
class Sub_Enumeration:
    def __init__(self,output_folder,file,github_token,gitlab_token,censys_api_id,censys_api_secret,chaos_key):
        self.output_folder=output_folder
        self.file=file
        self.github_token=github_token
        self.gitlab_token=gitlab_token
        self.censys_api_id=censys_api_id
        self.censys_api_secret=censys_api_secret
        self.chaos_key=chaos_key
    def knock_tool(self,domain,output_folder):
        print("[+] Knock Tool")
        #tool command  verified
        tool_command="python3 ~/Tools/knock/knockpy.py "+domain+' -o '+output_folder+'/KNOCK'+'> /dev/null 2>&1'
        #mov data from folder to single file
        system_command="mv "+output_folder+'/KNOCK/* ' + output_folder+'/knock.json' +'> /dev/null 2>&1'
        os.system(tool_command)
        os.system(system_command)
        system_command="rm -r "+output_folder+'/KNOCK'
        os.system(system_command)
    def subfinder_tool(self,domain,output_folder):
        print("[+] Subfinder Tool")
        #tool command verified
        tool_command="subfinder -d "+domain+" -silent"+" > "+output_folder+'/subfinder'
        
        os.system(tool_command)
    
    def assetfinder_tool(self,domain,output_folder):
        print("[+] Assetfinder Tool")
        #tool command verified
        tool_command="assetfinder -subs-only "+domain+' > '+output_folder+'/assetfinder'
        os.system(tool_command)
    
    def Github_tool(self,domain,output_folder,github_token):
        print("[+] Github Tool")
        #tool command verified
        tool_command="python3 ~/Tools/github-search/github-subdomains.py -d "+domain+' -t '+github_token+'>'+output_folder+'/github'
        os.system(tool_command)

    def Gitlab_tool(self,domain,output_folder,gitlab_token):
        print("[+] Gitlab Tool")
        #tool command verified
        tool_command="gitlab-subdomains -d "+domain+' -t '+gitlab_token+'>'+output_folder+'/gitlab'
        os.system(tool_command)
    
    def Censys_tool(self,domain,output_folder,censys_api_id,censys_api_secret):
        print("[+] Censys Tool")
        #tool command verified
        tool_command="python3 ~/Tools/censys-subdomain-finder/censys-subdomain-finder.py "+' --censys-api-id '+censys_api_id+' --censys-api-secret '+censys_api_secret+' -o '+output_folder+'/censys  '+domain+'  >/dev/null 2>&1'
        os.system(tool_command)
    
    def Waybackurl_tool(self,domain,output_folder):
        print("[+] Waybackurl Tool")
        #tool command verified
        tool_command="waybackurls "+domain+" |   unfurl -u domains >"+output_folder+'/waybackurl'
        os.system(tool_command)
    
    def Gau_tool(self,domain,output_folder):
        print("[+] Gau Tool")
        #tool command verified
        tool_command="gau "+domain+" |   unfurl -u domains >"+output_folder+'/gau'
        os.system(tool_command)

    def Cero_tool(self,domain,output_folder):
        print("[+] Cero Tool")
        #tool command verified
        tool_command="cero "+domain+" >"+output_folder+'/cero'
        os.system(tool_command)
    
    def Chaos_tool(self,domain,output_folder,chaos_key):
        print("[+] Chaos Tool")
        #tool command verified
        tool_command="chaos -d "+domain+" -silent -key "+chaos_key+" -o "+output_folder+'/chaos > /dev/null 2>&1'
        os.system(tool_command)
    
    def Archive_tool(self,domain,output_folder):
        print("[+] Archive Tool")
        #tool command  verified
        tool_command="""curl -sk "http://web.archive.org/cdx/search/cdx?url=*."""+domain+"""&output=txt&fl=original&collapse=urlkey&page=" | awk -F/ '{gsub(/:.*/, "", $3); print $3}' | sort -u > """+output_folder+'/archieve'
        os.system(tool_command)
    
    def Crt_tool(self,domain,output_folder):
        print("[+] Crt Tool")
        # Define the Bash command
        bash_command = f'curl -sk "https://crt.sh/?q=%25.{domain}&output=json" | tr "," "\\n" | awk -F\'"\' \'/name_value/ {{gsub(/\\*\\./, "", $4); gsub(/\\\\n/,"\\n",$4);print $4}}\''

        # Execute the Bash command using subprocess and capture the output
        output = subprocess.check_output(bash_command, shell=True, stderr=subprocess.STDOUT, text=True)
            
            # Specify the file path where you want to save the output
        output_file_path = output_folder+'/'+'crt'
            
            # Write the output to the file
        with open(output_file_path, "w") as output_file:
            output_file.write(output)
            

    def Hackertarget_tool(self,domain,output_folder):
        print("[+] Hackertarget Tool")
        #tool command verified
        tool_command='curl -sk "https://api.hackertarget.com/hostsearch/?q='+domain + '"'+" |  unfurl domains |grep -Eo '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' > "+output_folder +'/hackertarget'
        os.system(tool_command) 
    
    def Anubis_tool(self,domain,output_folder):
        print("[+] Anubis Tool")
        #tool command verified
        tool_command='curl -sk "https://jldc.me/anubis/subdomains/{0}" | jq -r '.format(domain)+"'.'"+' | grep -o "\w.*{}"'.format(domain)+" >"+output_folder+'/anubis'

        os.system(tool_command)
    
    def Certspotter_tool(self,domain,output_folder):
        print("[+] Certspotter Tool")
        tool_command='curl -sk "https://api.certspotter.com/v1/issuances?domain='+domain+'&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+"' +' > '+output_folder+'/certspotter'
        os.system(tool_command)
    def execute(self,domain,output_folder,github_token,gitlab_token,censys_api_id,censys_api_secret,chaos_key):
        self.assetfinder_tool(domain,output_folder)
        self.subfinder_tool(domain,output_folder)
        self.Waybackurl_tool(domain,output_folder)
        self.Gau_tool(domain,output_folder)
        self.Github_tool(domain,output_folder,github_token)
        self.Gitlab_tool(domain,output_folder,gitlab_token)
        self.Censys_tool(domain,output_folder,censys_api_id,censys_api_secret)
        self.Chaos_tool(domain,output_folder,chaos_key)
        self.Anubis_tool(domain,output_folder)
        self.Archive_tool(domain,output_folder)
        self.Cero_tool(domain,output_folder)
        self.Crt_tool(domain,output_folder)
        self.Certspotter_tool(domain,output_folder)
        self.Hackertarget_tool(domain,output_folder)
        self.knock_tool(domain,output_folder)
        print("[+] Enumerating Subdomain For {} Is Done".format(domain))

    def enumeration_phase(self):
        #check and create base outfolder
        if not os.path.exists(self.output_folder):
            # If it doesn't exist, create the folder
            os.makedirs(self.output_folder)
        #out folder enumeration
        domains_file=open(self.file,'r')
        domains=domains_file.readlines()
        for domain in domains:
            ##domain
            domain=domain.strip()
            
            output_folder=self.output_folder
            file_name=domain.replace('.','-')
            file_name=file_name.upper()
            ##output folder
            output_folder = output_folder +'/'+file_name
            #os.makedirs(output_folder)
            ##excute enumeration
            subdomain_folder = output_folder + '/Sub-Domains'
            os.makedirs(subdomain_folder)
            self.execute(domain,subdomain_folder,self.github_token,self.gitlab_token,self.censys_api_id,self.censys_api_secret,self.chaos_key)
            self.get_valid_subdomains(subdomain_folder,domain)
            time.sleep(50)
            ##httpx
            ##folder name
            httpx_folder=output_folder+'/Httpx'
            ##make that folder
            os.makedirs(httpx_folder)
            httpx_file=httpx_folder+'/HTTPX'
            uniqe_subdomains_file=subdomain_folder+'/uniqe_subdomains'
            self.httpx_enumeration(uniqe_subdomains_file,httpx_file)


           

        


            

            


    def get_valid_subdomains(self,subdomains_folder,domain):
        
        print("[+] Get Unique Subdomains")
        command=' cat '+subdomains_folder+'/*'+' | grep -Eo ' + """'([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})' | grep """+domain +" | sort | uniq "+ " > "+subdomains_folder+'/uniqe_subdomains'
        
        os.system(command)

    def httpx_enumeration(self,uniqe_subdomains_file,output_file):
        print('[+] Get Live Subdomains')
        command='httpx -l '+uniqe_subdomains_file+ ' -silent -o '+output_file +  ' > /dev/null 2>&1'
        
        os.system(command)
    
    

       

    


            



            


    

    
    
   
            
        
        

    
    
    
        
    
    
#define requirements of the tool to ruN
def Input_Requirements():
    argParser = argparse.ArgumentParser(
        description="""
        Enumeration tool.

        """,
        prog="enumeration.py",
        epilog="Created By akram"
    )

    argParser.add_argument('-f','--file',help='file contain list of domains')
    argParser.add_argument('-o','--output',help="output folder")
    

    

    args = argParser.parse_args()
    
    return args
def main():
    args=Input_Requirements()
    
    file=args.file
    output_folder=args.output
    
    
    github_token="GITHUB_TOKEN"
    gitlab_token="GITLAB_TOKEN"
    censys_api_id="CENSYS_API_ID"
    censys_api_secret="CENSYS_API_SECRET"
    chaos_key="CHAOS_KEY"
    
    inital_en=Sub_Enumeration(output_folder,file,github_token,gitlab_token,censys_api_id,censys_api_secret,chaos_key)
    inital_en.enumeration_phase()

if __name__ =="__main__":
    main()



