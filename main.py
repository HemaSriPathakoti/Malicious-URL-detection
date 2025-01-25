from flask import Flask, redirect, url_for, render_template, request,jsonify
from backend3 import predict

app = Flask(__name__)

@app.route('/',methods=["POST", "GET"])
def home():
    if request.method == "POST":
       
        data = request.form['url']

        res = predict(data)

        return render_template('result.html',result=res)
   
    return render_template('index2.html')   

if __name__ == '__main__':
    app.run(debug=True, port=5000)