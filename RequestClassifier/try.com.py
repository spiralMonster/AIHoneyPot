import requests

response=requests.get("https://jio.com/api/file")
print(response.text)