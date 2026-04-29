import http.server
import socketserver
import subprocess
import os
import io

PORT = 8000

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>PhantomRecon Scan</title>
    <style>
        body { background-color: #0c0c0c; color: #cccccc; font-family: 'Courier New', Courier, monospace; padding: 20px; font-size: 14px; }
        #terminal { white-space: pre-wrap; word-wrap: break-word; }
        .ansi-black { color: #0c0c0c; }
        .ansi-red { color: #c50f1f; }
        .ansi-green { color: #13a10e; }
        .ansi-yellow { color: #c19c00; }
        .ansi-blue { color: #0037da; }
        .ansi-magenta { color: #881798; }
        .ansi-cyan { color: #3a96dd; }
        .ansi-white { color: #cccccc; }
        .ansi-bold { font-weight: bold; }
        .ansi-dim { opacity: 0.7; }
    </style>
    <script>
        window.onload = function() {
            var term = document.getElementById('terminal');
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '/run_scan');
            xhr.onreadystatechange = function() {
                if (xhr.readyState > 2) {
                    term.innerHTML = xhr.responseText;
                    window.scrollTo(0, document.body.scrollHeight);
                }
            };
            xhr.send();
        };
    </script>
</head>
<body>
    <div id="terminal">Starting PhantomRecon scan...<br></div>
</body>
</html>"""

class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/run_scan':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            
            # Run the command and stream the output
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['FORCE_COLOR'] = '1'
            
            from ansi2html import Ansi2HTMLConverter
            conv = Ansi2HTMLConverter(inline=True)
            
            process = subprocess.Popen(
                ['python', '-m', 'phantomrecon', 'scan', 'scanme.nmap.org', '--profile', 'quick', '--no-ai'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                encoding='utf-8'
            )
            
            output = ""
            for line in iter(process.stdout.readline, ''):
                output += line
                html_chunk = conv.convert(output, full=False)
                # Just send the whole updated HTML chunk so the browser can replace it
                self.wfile.write(html_chunk.encode('utf-8'))
                self.wfile.flush()
            
            process.stdout.close()
            process.wait()

with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
