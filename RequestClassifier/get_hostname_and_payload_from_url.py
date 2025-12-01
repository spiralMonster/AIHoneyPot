def GetHostnameAndPayloadInfo(url):
    data=url.split("/")
    reached_hostname=False
    payload=[]
    for string in data:
        if reached_hostname:
            payload.append(string)

        if ".com" in string:
            hostname=string
            reached_hostname=True

    payload_url="/".join(payload)
    payload_url="/"+payload_url
    return (hostname,payload_url)

if __name__=="__main__":
    url="http://priyanshu23.pythonanywhere.com/api/file"
    host,payload_info=GetHostnameAndPayloadInfo(url)
    print(host,payload_info)
