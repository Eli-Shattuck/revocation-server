import requests
from itertools import product
import random

alph=list("0123456789ABCDEF")

comb = product(alph,alph,alph,alph) #2bytes
#comb = product(alph,alph,alph,alph) #2bytes
#comb = product(alph,alph) #2bytes

batch=[]

url="http://localhost:8080/new-ct/add-revocations"

submitted=0

for i in comb:
  flip = random.randint(0,1)
  if(flip==1):
    batch.append("00"+"".join(i))
    submitted+=1

data={"Serials":batch}

print("Submitting")
print(submitted)
r = requests.post(url,json=data)
print(r.status_code)
