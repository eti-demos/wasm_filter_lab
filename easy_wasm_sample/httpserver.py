from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime


HOST = "127.0.0.1"
PORT = 9999
class LogHTTP(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        self.wfile.write(bytes("helloworld", "utf-8"))
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        # client_addrss


        body = self.rfile.read(int(self.headers['Content-Length']))

        with open('http.log', 'a') as f:
            dateTime = datetime.now()

            f.writelines(f"[{dateTime}]")
            f.write(body.decode('utf-8'))
            f.write("\n")


        self.wfile.write(bytes("log successfully", "utf-8"))


server = HTTPServer((HOST, PORT), LogHTTP)
print("server now runing...")
server.serve_forever()
server.server_close()

