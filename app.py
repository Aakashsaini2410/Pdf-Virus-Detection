from flask import Flask, render_template, request
import os
import requests
import time

# Set up the Flask app
app = Flask(__name__)

# Directory to store uploaded files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Your VirusTotal API key
VIRUSTOTAL_API_KEY = '41bd12a0d31cb6ccf3e71cfc6ece28c0b98ab6a1634cb8cba3df5dd24b7cba99'  # Replace with your actual API key

# Function to scan the file with VirusTotal
def scan_file_with_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    with open(file_path, 'rb') as file:
        response = requests.post(url, headers=headers, files={"file": file})

    if response.status_code == 200:
        json_response = response.json()
        print(json_response)  # Log the full response for debugging
        return json_response.get('data', {}).get('id')  # Get the scan ID
    else:
        print(f"Error: {response.status_code} - {response.text}")  # Log any errors
        return None

def get_virustotal_scan_report(scan_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        print(json_response)  # Log the full response for debugging
        return json_response  # Return the entire report
    else:
        print(f"Error: {response.status_code} - {response.text}")  # Log any errors
        return None

# Route for displaying the file upload form
@app.route('/')
def index():
    return render_template('index.html')

# Route for handling file upload and scanning
@app.route('/scan', methods=['POST'])
def scan_file():
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        # Save the uploaded file to the uploads directory
        file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(file_path)

        # Scan the file with VirusTotal
        scan_id = scan_file_with_virustotal(file_path)
        if scan_id:
            print(f"Scan ID: {scan_id}")  # Debug print

            # Wait for a bit before fetching the report
            time.sleep(30)  # Increased wait time

            # Get the scan report
            report = get_virustotal_scan_report(scan_id)
            print(report)  # Debug print

            if report:
                analysis_results = report.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                result = {}
                for engine, details in analysis_results.items():
                    if details['result'] == 'malicious':  # Check the result attribute
                        result[engine] = details['reason']  # Store the engine and reason for detection

                if result:
                    return render_template('result.html', result=result, message="File is affected.")
                else:
                    return render_template('result.html', result={}, message="File is clean.")

            return render_template('result.html', result={}, message="Unable to retrieve scan report.")

        return render_template('result.html', result={}, message="Unable to retrieve scan ID.")

    return render_template('result.html', result={}, message="No file uploaded.")

# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)
