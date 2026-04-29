import http.server
import socketserver
import subprocess
import os
import time

PORT = 8001

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>PhantomRecon Guide</title>
    <style>
        body { background-color: #0c0c0c; color: #cccccc; font-family: 'Courier New', Courier, monospace; padding: 20px; font-size: 14px; line-height: 1.2; margin: 0; }
        #terminal { white-space: pre-wrap; word-wrap: break-word; }
        .prompt { color: #13a10e; font-weight: bold; }
        .command { color: #cccccc; font-weight: bold; }
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
            xhr.open('GET', '/stream_guide');
            var seenBytes = 0;
            xhr.onreadystatechange = function() {
                if(xhr.readyState > 2) {
                    var newData = xhr.responseText.substr(seenBytes);
                    term.innerHTML += newData;
                    seenBytes = xhr.responseText.length;
                    window.scrollTo(0, document.body.scrollHeight);
                }
            };
            xhr.send();
        };
    </script>
</head>
<body>
    <div id="terminal"></div>
</body>
</html>"""

class GuideHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))
        elif self.path == '/stream_guide':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            
            from ansi2html import Ansi2HTMLConverter
            conv = Ansi2HTMLConverter(inline=True)
            
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['FORCE_COLOR'] = '1'

            def simulate_typing(command):
                prompt = '<span class="prompt">root@kali:~#</span> '
                self.wfile.write(prompt.encode('utf-8'))
                self.wfile.flush()
                time.sleep(0.5)
                for char in command:
                    self.wfile.write(f'<span class="command">{char}</span>'.encode('utf-8'))
                    self.wfile.flush()
                    time.sleep(0.05)
                self.wfile.write(b'<br>')
                self.wfile.flush()
                time.sleep(0.2)

            def run_and_stream(command_args):
                process = subprocess.Popen(
                    command_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                    text=True,
                    encoding='utf-8'
                )
                
                for line in iter(process.stdout.readline, ''):
                    html_line = conv.convert(line, full=False)
                    # ansi2html sometimes wraps the whole thing in a div, let's just extract the inner HTML or use it as is
                    self.wfile.write((html_line + '<br>').encode('utf-8'))
                    self.wfile.flush()
                
                process.stdout.close()
                process.wait()
                self.wfile.write(b'<br>')
                self.wfile.flush()

            commands = [
                ("phantomrecon models", ["python", "-m", "phantomrecon", "models"]),
                ("phantomrecon scan scanme.nmap.org --profile quick --no-ai", ["python", "-m", "phantomrecon", "scan", "scanme.nmap.org", "--profile", "quick", "--no-ai"])
            ]

            for cmd_str, cmd_args in commands:
                simulate_typing(cmd_str)
                run_and_stream(cmd_args)
                time.sleep(1)

            self.wfile.write(b'<span class="prompt">root@kali:~#</span> ')
            self.wfile.flush()

with socketserver.TCPServer(("", PORT), GuideHandler) as httpd:
    print("serving guide at port", PORT)
    httpd.serve_forever()
