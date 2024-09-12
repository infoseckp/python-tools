import requests
from bs4 import BeautifulSoup


def scan(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')
    print(f'Found {len(forms)} forms on {url}')

    for form in forms:
        print(f'Form: {form}')
        # Add more detailed analysis here
