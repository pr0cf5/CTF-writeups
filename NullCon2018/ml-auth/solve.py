import requests
from keras.models import load_model
import numpy as np

def get_proba(ip):
       ip = np.array(ip, dtype='float32')/255
       # reshape profile as required by the trained model
       ip = ip.reshape([1,28,28,1])
       # load model
       predicted = model.predict(ip)[0][1]
       return predicted

def pack(arr):
       outstr = ""
       for x in arr:
              outstr += "0x%x"%x
       return outstr

model = load_model('./keras_model')
profile = [0 for _ in range(784)]

max_res = 0

for j in range(784):
       for i in range(0,0xFF,0x10):
              profile[j] = i
              res = get_proba(profile)
              if(max_res < res):
                     max_res = res
                     optimized_profile = pack(profile)
                     print("maximized to %2.4f"%max_res)

              if (max_res>=0.99):
                     break

url = "http://ml.ctf.nullcon.net/predict?profile={}".format(optimized_profile)
r = requests.get(url)
print(r.text)