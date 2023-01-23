#!/bin/bash

#Bash script for bug bounty recon using subfinder, httpx, dirsearch, gau, waybackurls, nmap, findomain

function ctrl_c(){
  echo -e "\n\n [!] Leaving...\n"
  exit 1
}


# Ctrl+C
trap ctrl_c INT

#Get the target domain
echo "Please enter the target domain:"
read domain
echo "A directory named bugbountyCrawler will be created right here..."
mkdir bugbountyEnum
cd bugbountyEnum

#Run subfinder to find subdomains

echo "Running subfinder..."
subfinder -d $domain -o subdomains.txt

#Run httpx on all discovered domains

echo "Running httpx, please be patient you only have to sit down and take a coffee..."
for i in $(cat subdomains.txt); do
	httpx -silent -title -threads 10 -follow-redirects -status-code -vhost -retries 3 -timeout 8 -recursive -o "$i_httpx" $i;
done

#Run dirsearch on all discovered subdomains

echo "Running dirsearch to enum all the subdomains discovered... relax..."
for i in $(cat subdomains.txt); do
	python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u $i -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e html,js,txt,php -t 100 -x 400,403,404,405 -f --plain-text-report=$i_dirsearch.txt;
done

#Run gau 

echo "Running gau, please be patient..."
gau $domain --fc 400,403,404,405 --from 202101 --mt html,js,txt,php --o gau.txt --providers wayback,commoncrawl,otx,urlscan --retries 3 --timeout 8 --subs --threads 100 --to 202101

#Run findomain

echo "Running findomain to enumerate more subdomains..."
findomain -t $domain

#Run nmap

echo "Running nmap, this may take a while..."
echo "Enumerating directories on the domain given at the start..."
nmap --script http-enum $domain

echo "Enumerating directories on the subdomains acquired from findomain..."
for dominio in $(findomain -t $domain); do
	nmap --script http-enum $dominio done
done

echo "Enumerating possible vulnerabilities on the domain given..."
nmap --script http-vulners-regex.nse [--script-args paths={"/"}] $domain

echo "Enumerating possible vulnerabilities on the subdomains from findomain..."
for dominio in $(findomain -t $domain); do
	nmap --script http-vulners-regex.nse [--script-args paths={"/"}] $dominio
done

echo "Enumerating services vulnerabilities for the domain given at the start..."
nmap -sV --script=vulscan/vulscan.nse $domain

echo "Enumerating services vulnerabilities for the subdomains acquired from findomain ..."
for dominio in $(findomain -t $domain); do

	nmap -sV --script=vulscan/vulscan.nse $dominio --script-args vulscanoutput='ID: {id} - Title: {title} - Version: {version} - Link: {link} ({matches})\n'
done
