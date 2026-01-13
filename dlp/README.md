# DLP - adding DLP payloads to MITRE Caldera 

DLP plugin has been created in case of testing Data Loss Prevention products via MITRE Caldera agents. No additional packages required.

## Installation

<pre><code>git clone https://github.com/csshark/CALDERA-PLUGINS.git
cd CALDERA-PLUGINS
mv dlp/ yourcaldera-dir/plugins</code></pre>

Remember to <b>enable</b> plugin in configfile (*local.yml* or your custom config).

Right now your Caldera should be extended by additional plugins verify abilities counter on dashboard with plugin enabled and disabled.

## Configuration (read before using dlp)

All parameters are configurable via Caldera facts (e.g., #{http.exfil.url}, #{smtp.server}). Set the appropriate facts in your operation before running.
<p>Go to fact sources → add fact sources.
