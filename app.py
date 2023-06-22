import hashlib
from flask import Flask, render_template, request, redirect

app = Flask(__name__, template_folder="./templates")

SESS_18_REQ_HDR = """GET /images/banner.png?cache=NGI6ZTE6ZDY6YTg6NjY6YmUK HTTP/1.1
Host: 54.80.43.46
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"""

SESS_18_RESP_HDR = """HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4340
Server: Werkzeug/2.0.1 Python/3.6.15
Date: Sun, 26 Sep 2021 00:59:31 GMT"""

SESS_19_REQ_HDR = """POST /upload HTTP/1.1
Host: 34.207.187.90
Accept-Encoding: identity
Content-Length: 18260"""

SESS_19_RESP_HDR = """HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2
Server: Werkzeug/2.0.1 Python/3.6.15
Date: Sun, 26 Sep 2021 00:59:32 GMT"""

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/python")
def python():
    return render_template("python.html")

@app.post("/python")
def python_form():
    pyc_f = request.files["pyc"]
    if pyc_f is None:
        return "error! please go back and try to upload your file again :)"

    pyc = pyc_f.read().strip()
    if len(pyc) in range(3240,3280) and b"\x33\x0d\x0d\x0a" in pyc[:0x10]:
        return redirect("/static/decompiled_script.py.txt")
    else:
        return "that file doesn't look correct, try recovering it a different way!"

@app.get("/pcap")
def pcap():
    return render_template("pcap.html")

@app.post("/pcap")
def pcap_results():
    pcap_f = request.files["pcap"]
    if pcap_f is None:
        return "error! please go back and try to upload your file again :)"

    pcap = pcap_f.read()

    if hashlib.md5(pcap,usedforsecurity=False).hexdigest() != "404d4efcb3b312b6c9950470d2dd6bed":
        return "this doesn't look like a valid pcap, did you upload the right file?"

    return render_template("pcap_results.html", sessions=[
        {
            "num": 18,
            "src": "192.168.88.134:44094",
            "dst": "54.80.43.46:80",
            "bytes_sent": 227,
            "bytes_recv": 4496,
            "req_hdrs": SESS_18_REQ_HDR,
            "resp_hdrs": SESS_18_RESP_HDR,
            "resp_url": "/static/stream18_response.txt"
        },
        {
            "num": 19,
            "src": "192.168.88.134:55912",
            "dst": "34.207.187.90:80",
            "bytes_sent": 18355,
            "bytes_recv": 227,
            "req_hdrs": SESS_19_REQ_HDR,
            "resp_hdrs": SESS_19_RESP_HDR,
            "req_url": "/static/stream19_request.txt",
            "resp_url": "/static/stream19_response.txt"
        }
    ])

if __name__ == "__main__":
    #app.run(debug=True)
    app.run()
