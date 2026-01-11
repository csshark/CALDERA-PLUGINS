# General purpose 
This doucment serves a companion to official MITRE Caldera documentation on the open source community contribution rights.

---

## Table of Contents
<ul>1. Server Config related to <a href=https://caldera.readthedocs.io/en/latest/Server-Configuration.html>Server Configuration<a> section.</ul>
<ul>2. Key files to modify for your custom production</ul> 
<ul>3. Custom Plugin Development guide</ul>


# 1. Server Config
There are plenty of ways to deploy Caldera. In this section the config .yaml file parsing is going to be described.

Instead of using a single local.yml file, it's recommended to create environment-specific configuration files. Let's cover this topic. Usually config file looks like that: 
<pre><code># conf/production.yml
ability_refresh: 60
api_key_blue: SECURE_API_KEY
api_key_red: SECURE_API_KEY
app.contact.dns.domain: caldera.myorganisation.com #! if you own a dns
app.contact.dns.socket: 0.0.0.0:8853
app.contact.gist: API_KEY
app.contact.html: /weather
app.contact.http: http://0.0.0.0:8888 #IMPORTANT: Change it if using ssl plugin for HTTPS connection
app.contact.slack.api_key: SLACK_TOKEN
app.contact.slack.bot_id: SLACK_BOT_ID
app.contact.slack.channel_id: SLACK_CHANNEL_ID
app.contact.tunnel.ssh.host_key_file: REPLACE_WITH_KEY_FILE_PATH
app.contact.tunnel.ssh.host_key_passphrase: REPLACE_WITH_KEY_FILE_PASSPHRASE
app.contact.tunnel.ssh.socket: 0.0.0.0:8022
app.contact.tunnel.ssh.user_name: sandcat
app.contact.tunnel.ssh.user_password: s4ndc4t!
app.contact.ftp.host: 0.0.0.0
app.contact.ftp.port: 2222
app.contact.ftp.pword: caldera
app.contact.ftp.server.dir: ftp_dir
app.contact.ftp.user: caldera_user
app.contact.tcp: 0.0.0.0:7010
app.contact.udp: 0.0.0.0:7011
app.contact.websocket: 0.0.0.0:7012
objects.planners.default: atomic # might be changed if user want different planner 
crypt_salt: "RandomlyGeneratedSaltValueHere"
encryption_key: "YourSecureEncryptionKey123!"
exfil_dir: /tmp/caldera
reachable_host_traits:
- remote.host.fqdn
- remote.host.ip
host: 0.0.0.0 #This address is not recommended, please use real Caldera addr.
plugins:
- access
- atomic
- compass
- debrief
- fieldmanual
- manx
- response
- sandcat
- stockpile
- training
port: 8888 # if you are ok with this port keep it as it is, however this port leads to many problems...
reports_dir: /tmp
auth.login.handler.module: default #or custom
requirements:
  go:
    command: go version
    type: installed_program
    version: 1.19
  python:
    attr: version
    module: sys
    type: python_module
    version: 3.9.0
# There is the painful part when you have to speak to administrator of LDAP implementation service. 
# Parameters may vary depending on your organisation LDAP config.
ldap:
  dn: cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org
  server: ldap://mycompanyldap.com
  user_attr: uid
  group_attr: objectClass
  red_group: organizationalperson
  # DON'T CREATE blue_group here - no need, if the red group attr is not satisfied user will be logged as blue team.
  # Additional note - I did rewrite the handler code to give support for Active Directory structure (support for filters such as OU= etc.)  
# User Management (disabled when using LDAP)
users:
  red:
    admin: "secure_password"
  blue:
    analyst: "secure_password"</code></pre>

Security first. All keys in this config file for production deployment should be at least ENCRYPTED! 
<pre><code>openssl rand -base64 32  # for encryption_key
openssl rand -base64 32  # for crypt_salt
openssl rand -base64 32  # for API keys</code></pre>



## 1.1 Port 8888 problems
Many users have discovered changing 8888 port in config does absolutely nothing. Use this bash to find where 8888 got bound or hardcoded (execute in caldera dir): 
<pre><code>find . -type f -exec grep -l "http://localhost:8888" {} \; | xargs -I {} sed -i 's|http://localhost:8888|http://192.168.0.10:8888|g' {}</code></pre>
In Caldera 5.3x < there was a problem with hardcoded port 8888 - Caldera was serving on port 8888 <b>always</b>. For now people are ignoring it in case of using <a href="https://github.com/mitre/ssl">ssl</a> plugin. There is a bypass by modyfing *server.py* file in main Caldera directory: 
<pre><code>async def start_server():
    await auth_svc.apply(app_svc.application, BaseWorld.get_config("users"))
    runner = web.AppRunner(app_svc.application)
    await runner.setup()
    
    # FORCE PORT , ex. 8222
    forced_port = 8222  # or BaseWorld.get_config("port") if u prefer to use config
    forced_host = BaseWorld.get_config("host") # we need to parse host for this function as well
    
    logging.info(f"FORCED - Starting server on {forced_host}:{forced_port}")
    await web.TCPSite(runner, forced_host, forced_port).start()</code></pre>

## 1.2 SSL plugin
The most important things to remember are: 
<li>SSL plugin uses .pem file with certificate and key in its content.</li>
<li>Agents deployed on the host sometimes have problems with HTTPS connection, to fix it they can access Caldera instance via backend directly (port 8888).</li>


## 2. Customizing MITRE Caldera for production
Here I am going to drop all files list after delivering project to client :) 

### Customized files list: 
<ul><li>default.py (login handler) <a href="">Go to File</a></li></ul>
<ul><li>DeployModal.vue (deployment of agents)</li></ul>
<ul><li>rest_svc.py</li></ul>
<ul><li>rest_api.py</li></ul>

<b>For custom images or logos</b>:
<pre><code>/plugins/magma/src/public/favicon.ico
/plugins/magma/src/assets/img/caldera-logo.png</code></pre>

Screenshot of customized dashboard: 
