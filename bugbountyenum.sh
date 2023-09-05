#!/bin/bash

# Bash script for bug bounty recon using various tools

function ctrl_c(){
  echo -e "\n\n [!] Leaving...\n"
  exit 1
}

# Ctrl+C
trap ctrl_c INT

# Validation
if [ -z "$1" ]; then
  echo "Usage: $0 <target_domain>"
  exit 1
fi

target_domain="$1"

# Create a directory for bug bounty enumeration
enum_dir="bugbountyEnum_$(date +'%Y%m%d_%H%M%S')"
mkdir "$enum_dir"
cd "$enum_dir"

# Run subfinder to find subdomains
echo "Running subfinder..."
subfinder -d "$target_domain" -o subdomains.txt

# Run additional subdomain enumeration tools (improvement 1)
echo "Running additional subdomain enumeration tools..."
assetfinder --subs-only "$target_domain" | sort -u >> subdomains.txt
amass enum -d "$target_domain" | sort -u >> subdomains.txt
crtsh "$target_domain" | sort -u >> subdomains.txt

# Run findomain
echo "Running findomain..."
findomain -t "$target_domain" -q | sort -u >> subdomains.txt

# Run httpx on discovered domains
echo "Running httpx..."
cat subdomains.txt | httpx -silent -title -threads 10 -follow-redirects -status-code -vhost -retries 3 -timeout 8 -recursive -o httpx.txt

# Run dirsearch on discovered subdomains
echo "Running dirsearch..."
python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -L subdomains.txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e html,js,txt,php -t 100 -x 400,403,404,405 -f --plain-text-report dirsearch.txt

# Run nmap scans for TCP and UDP ports (improvement 2)
echo "Running nmap TCP scans..."
nmap -p- --min-rate 1000 "$target_domain" -oN nmap_tcp.txt
echo "Running nmap UDP scans..."
nmap -sU --top-ports 100 "$target_domain" -oN nmap_udp.txt

# Run gau on all subdomains (improvement)
echo "Running gau on all subdomains..."
for subdomain in $(cat subdomains.txt); do
  gau "$subdomain" --fc 400,403,404,405 --from 202101 --mt html,js,txt,php --o "$subdomain_gau.txt" --providers wayback,commoncrawl,otx,urlscan --retries 3 --timeout 8 --subs --threads 100 --to 202101
done

# Run Nikto on all subdomains
echo "Running Nikto on all subdomains..."
for subdomain in $(cat subdomains.txt | sort -u); do
  echo "Running Nikto on $subdomain..."
  nikto -h "$subdomain" -output "nikto_$subdomain.txt"
done

# Run nmap scans for discovered subdomains (improvement 6)
echo "Running nmap scans for discovered subdomains..."
for subdomain in $(cat subdomains.txt | sort -u); do
  echo "Running nmap scans for $subdomain..."
  nmap --script http-enum "$subdomain" -oN "httpenum_$subdomain.txt"
  nmap --script http-vulners-regex.nse --script-args paths={"/"} "$subdomain" -oN "vulners_$subdomain.txt"
  nmap -sV --script=vulscan/vulscan.nse "$subdomain" --script-args vulscanoutput='ID: {id} - Title: {title} - Version: {version} - Link: {link} ({matches})\n' -oN "vulscan_$subdomain.txt"
done

echo "Bug bounty enumeration and scanning completed."
