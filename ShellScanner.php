<?php

/**
 * PHP Shell Scanner
 * Scans websites for potential web shells and malicious files
 * Includes self-test functionality and email notifications
 */

class ShellScanner {
    
    private $config;
    private $detectionPatterns;
    private $scanResults = [];
    private $emailer;
    private $logFile;
    
    public function __construct($configFile = 'config.json') {
        $this->loadConfig($configFile);
        $this->initializePatterns();
        $this->emailer = new EmailNotifier($this->config);
        $this->logFile = $this->config['log_file'] ?? 'scanner.log';
        $this->log("Shell Scanner initialized");
    }
    
    /**
     * Load configuration from JSON file
     */
    private function loadConfig($configFile) {
        if (!file_exists($configFile)) {
            throw new Exception("Configuration file not found: $configFile");
        }
        
        $this->config = json_decode(file_get_contents($configFile), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Invalid JSON in configuration file");
        }
    }
    
    /**
     * Initialize shell detection patterns
     */
    private function initializePatterns() {
        $this->detectionPatterns = [
            // PHP shell patterns
            'php_shells' => [
                '/eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                '/system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                '/exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                '/shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                '/passthru\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                '/base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                '/file_get_contents\s*\(\s*["\']php:\/\/input/',
                '/\$_(?:GET|POST|REQUEST)\s*\[\s*["\'][^"\']*["\']\s*\]\s*\(\s*\$_(?:GET|POST|REQUEST)/',
                '/create_function\s*\(\s*["\'][^"\']*["\']\s*,\s*\$_(?:GET|POST|REQUEST)/',
                '/preg_replace\s*\(\s*["\'][^"\']*e["\']/',
                '/assert\s*\(\s*\$_(?:GET|POST|REQUEST)/',
                '/\$\w+\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^]]+\];\s*\$\w+\(\);/',
            ],
            
            // Common shell file signatures
            'file_signatures' => [
                '/c99shell/',
                '/r57shell/',
                '/webshell/',
                '/backdoor/',
                '/shell_exec/',
                '/WSO\s*=/',
                '/FilesMan/',
                '/Php\s*Shell/',
                '/\$auth_pass\s*=/',
                '/\$default_action\s*=/',
                '/uname\s*-a/',
                '/id\s*&&\s*pwd/',
            ],
            
            // Suspicious function patterns
            'suspicious_functions' => [
                '/(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)/',
                '/file_put_contents\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)/',
                '/fwrite\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)/',
                '/fputs\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)/',
                '/chmod\s*\(\s*\$_(?:GET|POST|REQUEST)/',
                '/copy\s*\(\s*\$_(?:GET|POST|REQUEST)/',
                '/move_uploaded_file\s*\([^,]+,\s*\$_(?:GET|POST|REQUEST)/',
            ],
            
            // Encoded/obfuscated patterns
            'obfuscation' => [
                '/str_rot13\s*\(\s*["\'][^"\']{50,}/',
                '/base64_decode\s*\(\s*["\'][A-Za-z0-9+\/]{100,}/',
                '/gzinflate\s*\(\s*base64_decode/',
                '/eval\s*\(\s*gzinflate/',
                '/eval\s*\(\s*str_rot13/',
                '/\$\w+\s*=\s*["\'][A-Za-z0-9+\/=]{100,}["\'];\s*eval/',
            ]
        ];
    }
    
    /**
     * Scan a single URL for shells
     */
    public function scanUrl($url, $depth = 2) {
        $this->log("Starting scan of: $url");
        $visitedUrls = [];
        $foundShells = [];
        
        try {
            $this->crawlAndScan($url, $depth, $visitedUrls, $foundShells);
            
            $result = [
                'url' => $url,
                'timestamp' => date('Y-m-d H:i:s'),
                'shells_found' => count($foundShells),
                'details' => $foundShells,
                'status' => count($foundShells) > 0 ? 'INFECTED' : 'CLEAN'
            ];
            
            $this->scanResults[] = $result;
            $this->log("Scan completed for $url - Status: {$result['status']} - Shells found: {$result['shells_found']}");
            
            return $result;
            
        } catch (Exception $e) {
            $this->log("Error scanning $url: " . $e->getMessage());
            return [
                'url' => $url,
                'timestamp' => date('Y-m-d H:i:s'),
                'error' => $e->getMessage(),
                'status' => 'ERROR'
            ];
        }
    }
    
    /**
     * Crawl website and scan for shells
     */
    private function crawlAndScan($url, $depth, &$visitedUrls, &$foundShells) {
        if ($depth <= 0 || in_array($url, $visitedUrls)) {
            return;
        }
        
        $visitedUrls[] = $url;
        $this->log("Crawling: $url (depth: $depth)");
        
        // Get page content
        $content = $this->fetchUrl($url);
        if (!$content) {
            return;
        }
        
        // Scan current page for shells
        $shellDetection = $this->detectShells($content, $url);
        if ($shellDetection['is_shell']) {
            $foundShells[] = $shellDetection;
        }
        
        // Extract and follow links if depth allows
        if ($depth > 1) {
            $links = $this->extractLinks($content, $url);
            foreach ($links as $link) {
                if ($this->isValidTarget($link, $url)) {
                    $this->crawlAndScan($link, $depth - 1, $visitedUrls, $foundShells);
                }
            }
        }
    }
    
    /**
     * Fetch URL content
     */
    private function fetchUrl($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => $this->config['user_agent'] ?? 'Mozilla/5.0 (compatible; ShellScanner/1.0)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200 || !$content) {
            throw new Exception("Failed to fetch URL: $url (HTTP: $httpCode)");
        }
        
        return $content;
    }
    
    /**
     * Detect shells in content
     */
    private function detectShells($content, $url) {
        $detectedPatterns = [];
        $riskScore = 0;
        
        foreach ($this->detectionPatterns as $category => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content, $matches)) {
                    $detectedPatterns[] = [
                        'category' => $category,
                        'pattern' => $pattern,
                        'match' => $matches[0] ?? '',
                        'risk_score' => $this->getRiskScore($category)
                    ];
                    $riskScore += $this->getRiskScore($category);
                }
            }
        }
        
        $isShell = $riskScore >= ($this->config['risk_threshold'] ?? 50);
        
        return [
            'url' => $url,
            'is_shell' => $isShell,
            'risk_score' => $riskScore,
            'detected_patterns' => $detectedPatterns,
            'content_size' => strlen($content)
        ];
    }
    
    /**
     * Get risk score for pattern category
     */
    private function getRiskScore($category) {
        $scores = [
            'php_shells' => 100,
            'file_signatures' => 80,
            'suspicious_functions' => 60,
            'obfuscation' => 70
        ];
        
        return $scores[$category] ?? 30;
    }
    
    /**
     * Extract links from HTML content
     */
    private function extractLinks($content, $baseUrl) {
        $links = [];
        
        // Extract href attributes
        if (preg_match_all('/<a[^>]+href=["\']([^"\']+)["\'][^>]*>/i', $content, $matches)) {
            foreach ($matches[1] as $link) {
                $absoluteUrl = $this->makeAbsoluteUrl($link, $baseUrl);
                if ($absoluteUrl) {
                    $links[] = $absoluteUrl;
                }
            }
        }
        
        return array_unique($links);
    }
    
    /**
     * Convert relative URL to absolute
     */
    private function makeAbsoluteUrl($url, $baseUrl) {
        if (parse_url($url, PHP_URL_SCHEME)) {
            return $url; // Already absolute
        }
        
        $baseParts = parse_url($baseUrl);
        if (!$baseParts) {
            return null;
        }
        
        $base = $baseParts['scheme'] . '://' . $baseParts['host'];
        if (isset($baseParts['port'])) {
            $base .= ':' . $baseParts['port'];
        }
        
        if (strpos($url, '/') === 0) {
            return $base . $url;
        } else {
            $path = dirname($baseParts['path'] ?? '/');
            return $base . rtrim($path, '/') . '/' . $url;
        }
    }
    
    /**
     * Check if URL is valid target for scanning
     */
    private function isValidTarget($url, $originalUrl) {
        $urlParts = parse_url($url);
        $originalParts = parse_url($originalUrl);
        
        // Only scan same domain
        if ($urlParts['host'] !== $originalParts['host']) {
            return false;
        }
        
        // Skip non-PHP files unless configured otherwise
        $extension = pathinfo($urlParts['path'] ?? '', PATHINFO_EXTENSION);
        $allowedExtensions = $this->config['scan_extensions'] ?? ['php', 'phtml', 'php3', 'php4', 'php5', 'inc'];
        
        return in_array(strtolower($extension), $allowedExtensions) || empty($extension);
    }
    
    /**
     * Perform self-test
     */
    public function selfTest() {
        $this->log("Starting self-test...");
        $testResults = [];
        
        // Test 1: Pattern detection
        $testShellCode = '<?php eval($_GET["cmd"]); ?>';
        $detection = $this->detectShells($testShellCode, 'self-test');
        $testResults['pattern_detection'] = $detection['is_shell'] ? 'PASS' : 'FAIL';
        
        // Test 2: Configuration loading
        $testResults['config_loading'] = !empty($this->config) ? 'PASS' : 'FAIL';
        
        // Test 3: Email functionality
        try {
            $emailTest = $this->emailer->testConnection();
            $testResults['email_connection'] = $emailTest ? 'PASS' : 'FAIL';
        } catch (Exception $e) {
            $testResults['email_connection'] = 'FAIL: ' . $e->getMessage();
        }
        
        // Test 4: Log file writing
        try {
            $this->log("Self-test log entry");
            $testResults['log_writing'] = file_exists($this->logFile) ? 'PASS' : 'FAIL';
        } catch (Exception $e) {
            $testResults['log_writing'] = 'FAIL';
        }
        
        $overallStatus = in_array('FAIL', array_map(function($result) {
            return strpos($result, 'FAIL') === 0 ? 'FAIL' : 'PASS';
        }, $testResults)) ? 'FAIL' : 'PASS';
        
        $testResults['overall_status'] = $overallStatus;
        $this->log("Self-test completed - Status: $overallStatus");
        
        return $testResults;
    }
    
    /**
     * Send email notification of scan results
     */
    public function sendNotification($results) {
        if (empty($this->config['email']['enabled']) || !$this->config['email']['enabled']) {
            return false;
        }
        
        $infectedCount = 0;
        $totalScanned = count($results);
        
        foreach ($results as $result) {
            if ($result['status'] === 'INFECTED') {
                $infectedCount++;
            }
        }
        
        $subject = "Shell Scanner Report - $infectedCount threats found";
        $message = $this->formatEmailReport($results, $infectedCount, $totalScanned);
        
        return $this->emailer->send($subject, $message);
    }
    
    /**
     * Format email report
     */
    private function formatEmailReport($results, $infectedCount, $totalScanned) {
        $message = "PHP Shell Scanner Report\n";
        $message .= "========================\n\n";
        $message .= "Scan Date: " . date('Y-m-d H:i:s') . "\n";
        $message .= "URLs Scanned: $totalScanned\n";
        $message .= "Threats Found: $infectedCount\n\n";
        
        if ($infectedCount > 0) {
            $message .= "INFECTED SITES:\n";
            $message .= "---------------\n";
            
            foreach ($results as $result) {
                if ($result['status'] === 'INFECTED') {
                    $message .= "URL: " . $result['url'] . "\n";
                    $message .= "Shells Found: " . $result['shells_found'] . "\n";
                    
                    foreach ($result['details'] as $detail) {
                        $message .= "  - Risk Score: " . $detail['risk_score'] . "\n";
                        $message .= "  - Patterns: " . count($detail['detected_patterns']) . "\n";
                    }
                    $message .= "\n";
                }
            }
        } else {
            $message .= "All scanned sites are CLEAN.\n";
        }
        
        return $message;
    }
    
    /**
     * Get all scan results
     */
    public function getResults() {
        return $this->scanResults;
    }
    
    /**
     * Log message
     */
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = "[$timestamp] $message\n";
        file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    /**
     * Clear scan results
     */
    public function clearResults() {
        $this->scanResults = [];
    }
}

/**
 * Email notification class
 */
class EmailNotifier {
    
    private $config;
    
    public function __construct($config) {
        $this->config = $config['email'] ?? [];
    }
    
    /**
     * Send email notification
     */
    public function send($subject, $message) {
        if (empty($this->config['smtp_host'])) {
            return $this->sendWithMail($subject, $message);
        } else {
            return $this->sendWithSMTP($subject, $message);
        }
    }
    
    /**
     * Send email using PHP mail() function
     */
    private function sendWithMail($subject, $message) {
        $to = $this->config['to_email'];
        $from = $this->config['from_email'];
        
        $headers = "From: $from\r\n";
        $headers .= "Reply-To: $from\r\n";
        $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
        
        return mail($to, $subject, $message, $headers);
    }
    
    /**
     * Send email using SMTP
     */
    private function sendWithSMTP($subject, $message) {
        // Simple SMTP implementation
        $smtp = fsockopen($this->config['smtp_host'], $this->config['smtp_port'] ?? 587, $errno, $errstr, 30);
        
        if (!$smtp) {
            throw new Exception("SMTP connection failed: $errstr ($errno)");
        }
        
        // SMTP conversation
        $this->smtpCommand($smtp, '', '220');
        $this->smtpCommand($smtp, 'EHLO ' . $this->config['smtp_host'], '250');
        
        if (!empty($this->config['smtp_username'])) {
            $this->smtpCommand($smtp, 'STARTTLS', '220');
            stream_socket_enable_crypto($smtp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
            $this->smtpCommand($smtp, 'EHLO ' . $this->config['smtp_host'], '250');
            $this->smtpCommand($smtp, 'AUTH LOGIN', '334');
            $this->smtpCommand($smtp, base64_encode($this->config['smtp_username']), '334');
            $this->smtpCommand($smtp, base64_encode($this->config['smtp_password']), '235');
        }
        
        $this->smtpCommand($smtp, 'MAIL FROM: <' . $this->config['from_email'] . '>', '250');
        $this->smtpCommand($smtp, 'RCPT TO: <' . $this->config['to_email'] . '>', '250');
        $this->smtpCommand($smtp, 'DATA', '354');
        
        $emailData = "Subject: $subject\r\n";
        $emailData .= "From: " . $this->config['from_email'] . "\r\n";
        $emailData .= "To: " . $this->config['to_email'] . "\r\n";
        $emailData .= "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
        $emailData .= $message . "\r\n.\r\n";
        
        $this->smtpCommand($smtp, $emailData, '250');
        $this->smtpCommand($smtp, 'QUIT', '221');
        
        fclose($smtp);
        return true;
    }
    
    /**
     * Execute SMTP command
     */
    private function smtpCommand($smtp, $command, $expectedCode) {
        if ($command) {
            fwrite($smtp, $command . "\r\n");
        }
        
        $response = fgets($smtp, 512);
        $code = substr($response, 0, 3);
        
        if ($code !== $expectedCode) {
            throw new Exception("SMTP Error: Expected $expectedCode, got $code - $response");
        }
        
        return $response;
    }
    
    /**
     * Test email connection
     */
    public function testConnection() {
        try {
            if (empty($this->config['smtp_host'])) {
                return function_exists('mail');
            } else {
                $smtp = fsockopen($this->config['smtp_host'], $this->config['smtp_port'] ?? 587, $errno, $errstr, 10);
                if ($smtp) {
                    fclose($smtp);
                    return true;
                }
                return false;
            }
        } catch (Exception $e) {
            return false;
        }
    }
}

?>