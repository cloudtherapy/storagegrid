# 🛠️ StorageGRID Avahi Daemon Management (v4.3)

A robust utility script (`sg-avahi-fix.sh`) designed to manage and ensure the `avahi-daemon` service is running within StorageGRID VMs. The script connects to VMs via SSH, enters the `storagegrid-<VM>` container, and handles the avahi-daemon service in a secure and idempotent manner.

> **Note:** This is version 4.3 of the script, which includes WSL compatibility and improved error handling.

## ✨ Features

- 🔒 Secure authentication with multiple methods (SSH keys, keyring, GPG-encrypted files)
- 🔄 Idempotent operations - safe to run multiple times
- 🔍 Dry-run mode for previewing changes
- ⚡ Parallel execution for non-admin nodes
- 📝 Comprehensive logging
- 🔄 Automatic cleanup of temporary credentials
- 🛡️ Avoids problematic systemd wrappers in containers

## 🚀 Quick Start

1. Create a `servers.txt` file with your StorageGRID nodes (tab or space separated):
   ```
   # Name          IPAddress
   vm-sg-admin1    192.168.1.10
   vm-sg-storage1  192.168.1.11
   ```

2. Make the script executable:
   ```bash
   chmod +x sg-avahi-fix.sh
   ```

3. Run the script (you'll be prompted for the admin password):
   ```bash
   ./sg-avahi-fix.sh -s servers.txt
   ```
   
   Or set the password as an environment variable:
   ```bash
   SG_ADMIN_PASSWORD='your-password' ./sg-avahi-fix.sh -s servers.txt
   ```

4. For a dry run (no changes made):
   ```bash
   ./sg-avahi-fix.sh -s servers.txt --dry-run
   ```

## 📋 Prerequisites

- Bash 4.0+
- SSH client
- `sshpass` (for password-based authentication)
- `awk` (text processing)
- `sudo` or `su` access on target systems
- StorageGRID admin credentials

## 🛠️ Usage

### Basic Usage
```bash
./sg-avahi-fix.sh [options]
```

### Common Options
| Option | Description | Default |
|--------|-------------|---------|
| `-s, --servers FILE` | Path to servers list file | Required |
| `-u, --user NAME` | SSH username | `admin` |
| `-p, --port N` | SSH port | `8022` |
| `--dry-run` | Preview actions without making changes | `false` |
| `--debug` | Enable debug output | `false` |
| `-h, --help` | Show help message | - |

### Environment Variables
| Variable | Description |
|----------|-------------|
| `SG_ADMIN_PASSWORD` | Admin SSH password (if not set, you'll be prompted) |

### Authentication Methods
1. **Password Authentication (Default)**
   - The script will prompt for the password if `SG_ADMIN_PASSWORD` is not set
   - Example:
     ```bash
     export SG_ADMIN_PASSWORD='your-password'
     ./sg-avahi-fix.sh -s servers.txt
     ```

2. **SSH Key Authentication**
   - Set up SSH keys for password-less authentication
   - The script will use your default SSH key (~/.ssh/id_rsa) if available

## 🔒 Security

### Credential Handling
- Passwords are never logged or displayed
- Passwords are passed securely to sshpass
- The script uses `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` for SSH to avoid host key verification prompts
- For production use, consider setting up SSH keys for password-less authentication

### Best Practices
- Always use SSH keys when possible
- Store passwords using `--store-pass` instead of environment variables
- Run with `--dry-run` first to verify actions
- Review the log file after each run

## 🐛 Troubleshooting

## 🔍 Troubleshooting

### Common Issues

#### SSH Connection Failed
- Verify network connectivity to the StorageGRID nodes
- Check if SSH port (default: 8022) is open
- Ensure the admin user has sudo privileges
- Check that the server names in servers.txt match the VM hostnames

#### Password Authentication
```
Error: sshpass is required for non-interactive password authentication
```
Install sshpass:
```bash
# Ubuntu/Debian
sudo apt-get install sshpass

# RHEL/CentOS
sudo yum install sshpass

# macOS (using Homebrew)
brew install hudochenkov/sshpass/sshpass
```

#### Container Not Found
If you see errors about the container not being found:
- The script looks for containers starting with `storagegrid-`
- Ensure your VM hostnames in servers.txt match the container naming convention
- The script will try to find a container if an exact match isn't found

#### Service Management
If the script fails to start avahi-daemon, it tries multiple methods:
1. `service avahi-daemon start`
2. `systemctl start avahi-daemon`
3. `sv start avahi-daemon`

If all fail, check the container's service management system.

#### GPG Pinentry Issues
If you see:
```
gpg: public key decryption failed: Inappropriate ioctl for device
gpg: decryption failed: No secret key
```
Add to `~/.gnupg/gpg-agent.conf`:
```
allow-loopback-pinentry
```
Then restart the agent:
```bash
gpgconf --kill gpg-agent
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve this tool
- Special thanks to the open-source community for valuable resources
