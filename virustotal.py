import requests
import time

api_key = '65240d863116a673eb57c5c8482f2aac7f94df373b9acec1805674be6ec8c8b2'

def scan_url(api_key, url):
    params = {'apikey': api_key, 'url': url}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    response_json = response.json()
    print(response_json)
    return response_json['scan_id']

def scan_file(api_key, file_path):
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        params = {'apikey': api_key}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        response_json = response.json()
        print(response_json)
        return response_json['resource']

def get_report(api_key, resource, type):
    params = {
        'apikey': api_key,
        'resource': resource
    }
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip, My Python requests library example client or username"
    }
    if type == 'file':
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
    else:
        url = 'https://www.virustotal.com/vtapi/v2/url/report'

    report_response = requests.get(url, params=params, headers=headers)
    report_json = report_response.json()
    print(report_json)
    if 'positives' in report_json and report_json['positives'] > 0:
        print(f"The {type} is malicious. Detected by {report_json['positives']} engines.")
    else:
        print(f"The {type} is not malicious.")

# Main function
def main():
    type = input("Choose the scan type ('url' or 'file'): ")
    if type == 'file':
        file_path = input("Enter the path to the file: ")
        resource = scan_file(api_key, file_path)
    elif type == 'url':
        url = input("Enter the URL: ")
        resource = scan_url(api_key, url)
    else:
        print("Invalid type. Please enter 'url' or 'file'.")
        return

    # Wait for the scan to complete
    time.sleep(15)  # Adjust based on your needs
    get_report(api_key, resource, type)

if __name__ == "__main__":
    main()
