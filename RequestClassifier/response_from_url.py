import requests
import re


def ResponseFromURL(url,request_type):
    response = requests.get(url)

    if response.status_code == 200 and 'attachment' in response.headers.get('Content-Disposition', ''):
        content_disposition = response.headers.get('Content-Disposition', '')
        filename_match = re.search('filename="(.+)"', content_disposition)

        if filename_match:
            filename = filename_match.group(1)

        else:
            filename = "downloaded_file.txt"  # fallback

        if request_type=="normal":
            with open(filename, "wb") as f:
                f.write(response.content)

            print("File downloaded successfully to current folder.")
            print({
                "status": "success",
                "code": 200,
                "message": f"{filename} downloaded successfully"
            })

        elif request_type=="harmful":
            data={
                "status": "success",
                "code": 200,
                "message": f"{filename} downloaded successfully"
            }

            return data

        return None



    else:
        print("Failed to download file.")
        print("Response:", response.text)
        return None
