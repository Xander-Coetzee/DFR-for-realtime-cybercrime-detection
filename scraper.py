import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import smtplib
import os

# --- Configuration for Email Notifications ---
# To enable email notifications, set the following environment variables:
# GMAIL_USER: Your Gmail address
# GMAIL_APP_PASSWORD: Your Gmail app password
# RECIPIENT_EMAIL: The email address to send notifications to

def send_email_notification(threat_data):
    gmail_user = os.environ.get('GMAIL_USER')
    gmail_app_password = os.environ.get('GMAIL_APP_PASSWORD')
    recipient_email = os.environ.get('RECIPIENT_EMAIL')

    if not all([gmail_user, gmail_app_password, recipient_email]):
        print("Email notification credentials not set. Skipping email notification.")
        return

    sent_from = gmail_user
    to = [recipient_email]
    subject = 'Potential Cyber Threat Detected'
    body = f"A potential cyber threat has been detected.\n\nTimestamp: {threat_data['timestamp']}\nURL: {threat_data['url']}\nKeywords: {threat_data['keywords']}\n\nArticle Content:\n{threat_data['article_content']}"

    email_text = f"""From: {sent_from}
To: {', '.join(to)}
Subject: {subject}

{body}
"""

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_app_password)
        server.sendmail(sent_from, to, email_text)
        server.close()

        print('Email sent successfully!')
    except Exception as e:
        print(f'Something went wrong while sending the email: {e}')

def save_threat_to_file(threat_data):
    with open('threats.json', 'a') as f:
        json.dump(threat_data, f, indent=4)
        f.write('\n')

def scrape_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes

        soup = BeautifulSoup(response.content, 'html.parser')

        suspicious_keywords = ['credit card', 'password', 'social security number', 'login credentials', 'bank account', 'phishing']

        articles = soup.find_all('article')
        for article in articles:
            article_text = article.get_text(strip=True).lower()
            found_keywords = []
            for keyword in suspicious_keywords:
                if keyword in article_text:
                    found_keywords.append(keyword)
            
            if found_keywords:
                print(f"Potential threat found in article! Keywords: {found_keywords}")
                threat_data = {
                    'timestamp': datetime.now().isoformat(),
                    'url': url,
                    'keywords': found_keywords,
                    'article_content': article.get_text(strip=True)
                }
                save_threat_to_file(threat_data)
                send_email_notification(threat_data)
            else:
                print("No threats found in article.")

                print(f"Article Content: {article.get_text(strip=True)}")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching the URL: {e}")

if __name__ == '__main__':
    scrape_website('http://127.0.0.1:5000')