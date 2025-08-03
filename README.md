# PHP Shell Scanner

A comprehensive PHP web shell detection tool that scans websites for malicious shells and backdoors. Features include URL crawling, pattern-based detection, email notifications, and self-testing capabilities.

## 🚨 Security Warning

**This tool is designed for legitimate security testing and website auditing purposes only. Use it only on websites you own or have explicit permission to test. Unauthorized scanning of websites may violate laws and terms of service.**

## ✨ Features

- **Comprehensive Detection**: Scans for various types of PHP shells, backdoors, and malicious code
- **URL Crawling**: Automatically discovers and scans linked pages (configurable depth)
- **Pattern Matching**: Uses advanced regex patterns to detect obfuscated and encoded shells
- **Email Notifications**: Automatic email alerts for detected threats
- **Self-Test Functionality**: Built-in tests to verify scanner operation
- **Command Line Interface**: Easy-to-use CLI with multiple options
- **JSON Output**: Export scan results for further analysis
- **Configurable**: Extensive configuration options via JSON file

## 📋 Requirements

- PHP 7.4 or higher
- cURL extension enabled
- Write permissions for log files
- SMTP server (optional, for email notifications)

## 🚀 Installation

1. Clone or download the scanner files:
```bash
git clone <repository-url>
cd php-shell-scanner
```

2. Make the scanner executable:
```bash
chmod +x scanner.php
```

3. Configure email settings (optional):
```bash
nano config.json
```

4. Run self-test to verify installation:
```bash
php scanner.php --self-test
```

## ⚙️ Configuration

Edit `config.json` to customize the scanner:

### Email Configuration
```json
{
    "email": {
        "enabled": true,
        "to_email": "security@yourdomain.com",
        "from_email": "scanner@yourdomain.com",
        "smtp_host": "smtp.yourdomain.com",
        "smtp_port": 587,
        "smtp_username": "your_username",
        "smtp_password": "your_password"
    }
}
```

### Scanner Settings
```json
{
    "risk_threshold": 50,
    "max_scan_depth": 3,
    "scan_extensions": ["php", "phtml", "php3", "php4", "php5", "inc"],
    "timeout": 30
}
```

## 📖 Usage

### Basic Usage
```bash
php scanner.php https://example.com
```

### Advanced Usage
```bash
# Scan multiple URLs with verbose output
php scanner.php -v https://site1.com https://site2.com

# Set custom crawl depth
php scanner.php -d 3 https://example.com

# Save results to JSON file
php scanner.php -o results.json https://example.com

# Disable email notifications
php scanner.php --no-email https://example.com

# Use custom configuration file
php scanner.php -c custom-config.json https://example.com
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help information |
| `-v, --verbose` | Enable verbose output |
| `-t, --self-test` | Run self-test |
| `-d, --depth <num>` | Set crawling depth (default: 2) |
| `-c, --config <file>` | Use custom config file |
| `-o, --output <file>` | Save results to JSON file |
| `--no-email` | Disable email notifications |

## 🔍 Detection Capabilities

The scanner detects various types of malicious code:

### PHP Shells
- Direct command execution via `eval()`, `system()`, `exec()`
- File manipulation functions with user input
- Dynamic function calls using superglobals
- Base64 encoded payloads

### Common Shell Signatures
- c99shell, r57shell, WSO shell patterns
- Backdoor and webshell keywords
- File manager signatures
- Authentication bypass patterns

### Obfuscation Techniques
- Base64 encoding/decoding chains
- String rotation (ROT13)
- Compressed payloads (gzinflate)
- Dynamic function creation

## 📊 Output Format

### Console Output
```
✅ CLEAN (2.45s)
🚨 INFECTED (1.23s)
   Shells detected: 2
❌ ERROR (0.15s)
   Error: Connection timeout
```

### JSON Output
```json
{
    "scan_date": "2024-01-15 14:30:25",
    "scanner_version": "1.0",
    "results": [
        {
            "url": "https://example.com",
            "timestamp": "2024-01-15 14:30:25",
            "status": "INFECTED",
            "shells_found": 1,
            "details": [
                {
                    "url": "https://example.com/admin.php",
                    "risk_score": 100,
                    "detected_patterns": [
                        {
                            "category": "php_shells",
                            "pattern": "/eval\\s*\\(\\s*\\$_GET/",
                            "match": "eval($_GET[\"cmd\"])",
                            "risk_score": 100
                        }
                    ]
                }
            ]
        }
    ]
}
```

## 🧪 Self-Test

Run the built-in self-test to verify all components:

```bash
php scanner.php --self-test
```

This tests:
- Pattern detection algorithms
- Configuration loading
- Email connectivity
- Log file writing
- Overall system health

## 📧 Email Notifications

The scanner can send automatic email notifications when threats are detected:

### SMTP Configuration
For external SMTP servers (recommended):
```json
{
    "email": {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_username": "your-email@gmail.com",
        "smtp_password": "your-app-password"
    }
}
```

### Local Mail Configuration
For systems with local mail configured:
```json
{
    "email": {
        "smtp_host": "",
        "to_email": "admin@localhost",
        "from_email": "scanner@localhost"
    }
}
```

## 🛠️ Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod +x scanner.php
   chmod 755 .
   ```

2. **cURL Not Available**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install php-curl
   
   # CentOS/RHEL
   sudo yum install php-curl
   ```

3. **Email Not Sending**
   - Check SMTP credentials
   - Verify firewall settings
   - Test with `--self-test`

4. **False Positives**
   - Adjust `risk_threshold` in config
   - Review detection patterns
   - Use whitelist domains

### Log Files

Check `scanner.log` for detailed operation logs:
```bash
tail -f scanner.log
```

## 🔒 Security Considerations

1. **Permissions**: Run with minimal required permissions
2. **Network**: Use firewalls to restrict outbound connections
3. **Credentials**: Store email credentials securely
4. **Logs**: Regularly rotate and secure log files
5. **Updates**: Keep PHP and extensions updated

## 📈 Performance Tips

1. **Crawl Depth**: Lower depth for faster scans
2. **Timeout**: Adjust based on network conditions
3. **Extensions**: Limit scan extensions to relevant files
4. **Parallel Scanning**: Use multiple instances for large scans

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new detection patterns
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided "as is" without warranty. The authors are not responsible for any damage or legal issues arising from its use. Always ensure you have proper authorization before scanning any website.

## 📞 Support

For issues and questions:
- Check the troubleshooting section
- Review log files
- Run self-test for diagnostics
- Create an issue in the repository

---

**Remember: Only scan websites you own or have explicit permission to test!**