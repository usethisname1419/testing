import subprocess
import csv
import json
import openai
import whois

# Set your OpenAI API key here
openai.api_key = 'sk-proj-jfJ6BWlU3hoLhr9YJqH2T3BlbkFJwaDvXNv33OqjYbiKpf8X'

def convert_pcap_to_csv(pcap_file, csv_file):
    tshark_command = [
        'tshark', '-r', pcap_file, '-T', 'fields', '-E', 'separator=,', '-E', 'quote=d', '-E', 'header=y',
        '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'http.host', '-e', 'http.request.full_uri', 
        '-e', 'dns.qry.name', '-e', 'dns.a', '-e', 'ssl.handshake.extensions_server_name'
    ]
    with open(csv_file, 'w') as f:
        subprocess.run(tshark_command, stdout=f)

def extract_data_from_csv(csv_file):
    data = []
    with open(csv_file, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            data.append(row)
    return data

def perform_whois_lookup(ip_address):
    try:
        w = whois.whois(ip_address)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "referral_url": w.referral_url,
            "updated_date": w.updated_date,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "dnssec": w.dnssec
        }
    except Exception as e:
        return {"error": str(e)}

def summarize_data(data):
    summary = []
    for entry in data:
        whois_data_src = perform_whois_lookup(entry.get('ip.src'))
        whois_data_dst = perform_whois_lookup(entry.get('ip.dst'))
        summary.append({
            "frame_number": entry.get('frame.number'),
            "time": entry.get('frame.time'),
            "source_ip": entry.get('ip.src'),
            "source_ip_whois": whois_data_src,
            "destination_ip": entry.get('ip.dst'),
            "destination_ip_whois": whois_data_dst,
            "http_host": entry.get('http.host'),
            "full_uri": entry.get('http.request.full_uri'),
            "dns_query": entry.get('dns.qry.name'),
            "dns_answer": entry.get('dns.a'),
            "ssl_server_name": entry.get('ssl.handshake.extensions_server_name')
        })
    return summary

def ask_chatgpt(prompt):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1500
    )
    return response.choices[0].message['content'].strip()

def analyze_pcap(pcap_file):
    csv_file = 'output.csv'
    convert_pcap_to_csv(pcap_file, csv_file)
    data = extract_data_from_csv(csv_file)
    summary = summarize_data(data)
    prompt = f"Analyze the following network data to identify third-party data sharing:\n{json.dumps(summary, indent=2)}"
    response = ask_chatgpt(prompt)
    print("ChatGPT Analysis Report:")
    print(response)

# Specify your pcap file here
pcap_file = 'testpcap.pcap'
analyze_pcap(pcap_file)

