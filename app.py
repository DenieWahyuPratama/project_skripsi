from flask import Flask, request, render_template
import requests
import json
import pandas as pd
import numpy as np
import csv
import pickle

app = Flask(__name__)
API_key = '5c363ea13b7b52cb2b135f286123015adf72efb43f0b0ee4e4cfb20acb5c1f31'
scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
result_file = 'C:/Users/Asus/Desktop/project2/results.csv'
classifier_file = 'C:/Users/Asus/Desktop/project2/classifier.pkl'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_url/', methods=['POST'])
def check_url():
    url = request.form['url']
    scan_response = requests.post(scan_url, params={'apikey': API_key, 'url': url})
    scan_data = json.loads(scan_response.text)

    if scan_data['response_code'] == 1:
        scan_id = scan_data['scan_id']
        report_response = requests.get(report_url, params={'apikey': API_key, 'resource': scan_id})
        report_data = json.loads(report_response.text)
        if report_data['response_code'] == 1:
            try:
                df = pd.read_csv(result_file)
            except FileNotFoundError:
                with open(result_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Vendor", "Nilai"])
                    df = pd.read_csv(result_file)
            for item in report_data['scans']:
                result = report_data['scans'][item]['result']
                if result in ['clean site', 'unrated site']:
                    nilai = 0
                elif result in ['phishing site', 'malware site', 'malicious site', 'spam site', 'suspicious site']:
                    nilai = 2
                else:
                    continue
                if item in df['Vendor'].values:
                    index = df.index[df['Vendor'] == item].tolist()[0]
                    df.at[index, 'Nilai'] = nilai
                else:
                    continue
            df.to_csv(result_file, index=False)
                    
            df = pd.read_csv(result_file)
            df.fillna(value=1, inplace=True)
            df.to_csv(result_file, index=False)
            with open(classifier_file, 'rb') as file:
                classifier = pickle.load(file)
            data = df['Nilai'].values.reshape(1,-1)
            data = np.reshape(data, (1, -1))
            #data = np.resize(data, (data.shape[0], 128))
            predictions = classifier.predict(data)
    else:
        return "Url Tidak Ada Di Database"

    if predictions[0] == 0:
        hasil = "Url Aman"
    else:
        hasil = "Url Berbahaya"

    df = pd.read_csv(result_file)
    df.drop(columns = ['Nilai'],inplace=True)
    df.to_csv(result_file, index=False)
    return render_template('hasil.html', hasil=hasil)

if __name__ == '__main__':
    app.run(debug=True)
