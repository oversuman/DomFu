import hashlib

apikey = "FFFFFFFFFF"
api_key = hashlib.sha256(str(apikey).encode('utf-8')).hexdigest()


print(api_key)
print(api_key_de)
