import requests

def ContextFromInternet(payload_data):
    sources=[
        f"https://google.com{payload_data}",
        f"https://jio.com{payload_data}"
    ]

    context=[]
    for url in sources:
        response=requests.get(url)
        context.append(response.text)

    return context

if __name__=="__main__":
    print(ContextFromInternet("/api/file"))



