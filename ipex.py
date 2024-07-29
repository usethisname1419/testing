import re
import socket

def extract_urls(text):
    # Regex pattern to extract URLs from the text
    url_pattern = re.compile(
        r'https?://'  # http:// or https://
        r'(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    )
    return url_pattern.findall(text)

def resolve_url_to_ip(url):
    try:
        # Extract the hostname from the URL
        hostname = re.findall(r'https?://([^/]+)', url)[0]
        # Resolve the hostname to an IP address
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(f"Error resolving {url}: {e}")
        return None

def main(input_file, output_file):
    # Read the input file
    with open(input_file, 'r') as file:
        text = file.read()

    # Extract URLs from the text
    urls = extract_urls(text)

    # Resolve URLs to IP addresses
    ips = set()
    for url in urls:
        ip = resolve_url_to_ip(url)
        if ip:
            ips.add(ip)

    # Write IP addresses to the output file
    with open(output_file, 'w') as file:
        for ip in ips:
            file.write(ip + '\n')

    # Generate a single Wireshark filter for all IPs
    if ips:
        wireshark_filter = " || ".join([f"ip.addr == {ip}" for ip in ips])
    else:
        wireshark_filter = ""

    # Print the combined Wireshark filter
    print("Combined Wireshark filter:")
    print(wireshark_filter)

if __name__ == '__main__':
    input_file = 'pokemongoconnections.txt'  # Path to your input file
    output_file = 'output_ips.txt'  # Path to your output file
    main(input_file, output_file)

