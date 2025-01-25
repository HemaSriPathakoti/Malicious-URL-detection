import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from backend2 import having_ip_address, abnormal_url,google_index, count_dot, count_www, count_atrate, no_of_dir, no_of_embed, suspicious_words,letter_count
from backend2 import shortening_service, count_https,count_http,count_per,count_ques, count_hyphen, count_equal,url_length,hostname_length, fd_length, tld_length, digit_count

df = pd.read_csv("C://Users//Hemasri Pathakoti//Desktop//Mini_Major//Malicious_URL_detection//Flask//preprocessed_data.csv")

label_encoder = LabelEncoder()
df['type_code'] = label_encoder.fit_transform(df['type'])

# 0-benign, 1-defacement, 3-phishing, 2-malware
# print(df.columns)

X = df[['use_of_ip','abnormal_url','google_index', 'count.', 'count-www', 'count@',
       'count_dir', 'count_embed_domain','sus_url', 'short_url','count_https',
       'count_http', 'count%', 'count?', 'count-', 'count=', 'url_length', 'hostname_length', 'fd_length', 'tld_length', 'count_digits',
       'count_letters']]


Y = df['type_code']

# print(X.shape)
# print(Y.shape)
# print(X_train.shape , Y_train.shape)
# print(X_test.shape , Y_test.shape)
# print(X_train.values)
# print(X_test.values)
# y_pred = classifier.predict(X_test)


X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size= 0.2 , shuffle = True, random_state = 42)
classifier = RandomForestClassifier(n_estimators = 100, random_state=42)
classifier.fit(X_train, Y_train)
# print(X_test.head())

def model(url):
      
       # predict=classifier.predict(X_test)
       # print(accuracy_score(Y_test, predict))

       y_pred = classifier.predict(url.reshape(1,-1))
       output = y_pred[0]
       
       print(output)
       if(output==0):
              return "Benign"
       elif(output==1):
              return "Defacement"
       elif(output==2):
              return "Malware"
       else:
              return "Phishing"
       
       

def predict(url):
       arr = []
       arr.append(having_ip_address(url))
       arr.append(abnormal_url(url))
       arr.append(google_index(url))
       arr.append(count_dot(url))
       arr.append(count_www(url))
       arr.append(count_atrate(url))
       arr.append(no_of_dir(url))
       arr.append(no_of_embed(url))
       arr.append(suspicious_words(url))
       arr.append(shortening_service(url))
       arr.append(count_https(url))
       arr.append(count_http(url))
       arr.append(count_per(url))
       arr.append(count_ques(url))
       arr.append(count_hyphen(url))
       arr.append(count_equal(url))
       arr.append(url_length(url))
       arr.append(hostname_length(url))
       arr.append(fd_length(url))
       arr.append(tld_length(url))
       arr.append(digit_count(url))
       arr.append(letter_count(url))
       Array = np.array(arr)
       print(Array)
       return model(Array)
       

# predict("http://www.ajio.com")