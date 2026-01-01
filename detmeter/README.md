# detmeter (alpha test stage)

MITRE Caldera plugin that allows user to provide real time comparison between blue agent detections and SIEM detections. Plugin is flexible enough to provide configuration with GUI. 

## start Caldera with detmeter
In caldera config enable plugin by adding detmeter to plugins list: 
<pre><code>- ssl
- human
- magma 
- detmeter #enable me!
- manx </code></pre>

For now detmeter is under active deployment and modification. Full release planned for end of the January 2025 

<b>Important</b>: please note that plugin does not verify if the correct rule got triggered, it just checks if rule got triggered at the same moment that blue agent's did.
