#!/usr/bin/env php
<?php

/**
 * PHP Shell Scanner - Command Line Interface
 * Usage: php scanner.php [options] <url1> [url2] [url3] ...
 */

require_once 'ShellScanner.php';

class ScannerCLI {
    
    private $scanner;
    private $options = [];
    
    public function __construct() {
        $this->parseArguments();
        $this->initializeScanner();
    }
    
    /**
     * Parse command line arguments
     */
    private function parseArguments() {
        global $argv;
        
        $this->options = [
            'urls' => [],
            'depth' => 2,
            'config' => 'config.json',
            'self_test' => false,
            'verbose' => false,
            'email' => true,
            'output' => null,
            'help' => false
        ];
        
        for ($i = 1; $i < count($argv); $i++) {
            $arg = $argv[$i];
            
            switch ($arg) {
                case '-h':
                case '--help':
                    $this->options['help'] = true;
                    break;
                    
                case '-v':
                case '--verbose':
                    $this->options['verbose'] = true;
                    break;
                    
                case '-t':
                case '--self-test':
                    $this->options['self_test'] = true;
                    break;
                    
                case '--no-email':
                    $this->options['email'] = false;
                    break;
                    
                case '-d':
                case '--depth':
                    if (isset($argv[$i + 1])) {
                        $this->options['depth'] = (int)$argv[++$i];
                    }
                    break;
                    
                case '-c':
                case '--config':
                    if (isset($argv[$i + 1])) {
                        $this->options['config'] = $argv[++$i];
                    }
                    break;
                    
                case '-o':
                case '--output':
                    if (isset($argv[$i + 1])) {
                        $this->options['output'] = $argv[++$i];
                    }
                    break;
                    
                default:
                    if (strpos($arg, 'http') === 0) {
                        $this->options['urls'][] = $arg;
                    }
                    break;
            }
        }
    }
    
    /**
     * Initialize the scanner
     */
    private function initializeScanner() {
        try {
            $this->scanner = new ShellScanner($this->options['config']);
        } catch (Exception $e) {
            $this->output("Error: " . $e->getMessage(), true);
            exit(1);
        }
    }
    
    /**
     * Run the scanner
     */
    public function run() {
        if ($this->options['help']) {
            $this->showHelp();
            return;
        }
        
        $this->showBanner();
        
        if ($this->options['self_test']) {
            $this->runSelfTest();
            return;
        }
        
        if (empty($this->options['urls'])) {
            $this->output("Error: No URLs provided. Use -h for help.", true);
            exit(1);
        }
        
        $this->scanUrls();
    }
    
    /**
     * Show application banner
     */
    private function showBanner() {
        echo "\n";
        echo "██████╗ ██╗  ██╗██████╗     ███████╗██╗  ██╗███████╗██╗     ██╗         ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ \n";
        echo "██╔══██╗██║  ██║██╔══██╗    ██╔════╝██║  ██║██╔════╝██║     ██║         ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗\n";
        echo "██████╔╝███████║██████╔╝    ███████╗███████║█████╗  ██║     ██║         ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝\n";
        echo "██╔═══╝ ██╔══██║██╔═══╝     ╚════██║██╔══██║██╔══╝  ██║     ██║         ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗\n";
        echo "██║     ██║  ██║██║         ███████║██║  ██║███████╗███████╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║\n";
        echo "╚═╝     ╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n";
        echo "\n";
        echo "PHP Web Shell Scanner v1.0 - Security Analysis Tool\n";
        echo "====================================================\n\n";
    }
    
    /**
     * Show help information
     */
    private function showHelp() {
        echo "PHP Shell Scanner - Usage Information\n";
        echo "=====================================\n\n";
        echo "Usage: php scanner.php [options] <url1> [url2] [url3] ...\n\n";
        echo "Options:\n";
        echo "  -h, --help           Show this help message\n";
        echo "  -v, --verbose        Enable verbose output\n";
        echo "  -t, --self-test      Run self-test to verify scanner functionality\n";
        echo "  -d, --depth <num>    Set crawling depth (default: 2)\n";
        echo "  -c, --config <file>  Use custom configuration file (default: config.json)\n";
        echo "  -o, --output <file>  Save results to JSON file\n";
        echo "  --no-email           Disable email notifications\n\n";
        echo "Examples:\n";
        echo "  php scanner.php https://example.com\n";
        echo "  php scanner.php -d 3 -v https://site1.com https://site2.com\n";
        echo "  php scanner.php --self-test\n";
        echo "  php scanner.php -o results.json https://example.com\n\n";
        echo "Configuration:\n";
        echo "  Edit config.json to customize scanning parameters and email settings.\n\n";
    }
    
    /**
     * Run self-test
     */
    private function runSelfTest() {
        $this->output("Running Self-Test...", false);
        $this->output("===================\n", false);
        
        $results = $this->scanner->selfTest();
        
        foreach ($results as $test => $result) {
            $status = (strpos($result, 'FAIL') === 0) ? '❌ FAIL' : '✅ PASS';
            $testName = ucwords(str_replace('_', ' ', $test));
            
            if ($test === 'overall_status') {
                $this->output("\n" . str_repeat('-', 40), false);
                $this->output("Overall Status: $status", false);
            } else {
                $this->output(sprintf("%-20s: %s", $testName, $status), false);
                if (strpos($result, 'FAIL:') === 0) {
                    $this->output("  Error: " . substr($result, 6), false);
                }
            }
        }
        
        if ($results['overall_status'] === 'PASS') {
            $this->output("\n✅ Scanner is ready for operation!", false);
        } else {
            $this->output("\n❌ Scanner has issues that need to be resolved.", true);
            exit(1);
        }
    }
    
    /**
     * Scan provided URLs
     */
    private function scanUrls() {
        $totalUrls = count($this->options['urls']);
        $results = [];
        
        $this->output("Starting scan of $totalUrls URL(s)...", false);
        $this->output("Crawl depth: {$this->options['depth']}", false);
        $this->output(str_repeat('-', 50) . "\n", false);
        
        foreach ($this->options['urls'] as $index => $url) {
            $urlNum = $index + 1;
            $this->output("[$urlNum/$totalUrls] Scanning: $url", false);
            
            $startTime = microtime(true);
            $result = $this->scanner->scanUrl($url, $this->options['depth']);
            $endTime = microtime(true);
            
            $duration = round($endTime - $startTime, 2);
            $result['scan_duration'] = $duration;
            
            $this->displayResult($result);
            $results[] = $result;
            
            if ($this->options['verbose']) {
                $this->displayDetailedResult($result);
            }
        }
        
        $this->displaySummary($results);
        
        // Save results to file if requested
        if ($this->options['output']) {
            $this->saveResults($results);
        }
        
        // Send email notification if enabled
        if ($this->options['email']) {
            $this->output("\nSending email notification...", false);
            try {
                $sent = $this->scanner->sendNotification($results);
                $this->output($sent ? "✅ Email sent successfully" : "❌ Email sending failed", false);
            } catch (Exception $e) {
                $this->output("❌ Email error: " . $e->getMessage(), true);
            }
        }
    }
    
    /**
     * Display scan result
     */
    private function displayResult($result) {
        $status = $result['status'];
        $icon = '✅';
        $color = '';
        
        switch ($status) {
            case 'INFECTED':
                $icon = '🚨';
                $color = "\033[31m"; // Red
                break;
            case 'ERROR':
                $icon = '❌';
                $color = "\033[33m"; // Yellow
                break;
            case 'CLEAN':
                $icon = '✅';
                $color = "\033[32m"; // Green
                break;
        }
        
        $duration = $result['scan_duration'] ?? 0;
        $this->output(sprintf(
            "%s %s%s\033[0m (%.2fs)",
            $icon,
            $color,
            $status,
            $duration
        ), false);
        
        if ($status === 'INFECTED') {
            $this->output("   Shells detected: {$result['shells_found']}", false);
        } elseif ($status === 'ERROR') {
            $this->output("   Error: {$result['error']}", false);
        }
    }
    
    /**
     * Display detailed result information
     */
    private function displayDetailedResult($result) {
        if ($result['status'] === 'INFECTED' && !empty($result['details'])) {
            $this->output("   Detailed Analysis:", false);
            foreach ($result['details'] as $detail) {
                $this->output(sprintf("     Risk Score: %d", $detail['risk_score']), false);
                $this->output(sprintf("     Patterns Found: %d", count($detail['detected_patterns'])), false);
                
                foreach ($detail['detected_patterns'] as $pattern) {
                    $this->output(sprintf("       - %s: %s", 
                        ucwords($pattern['category']), 
                        substr($pattern['match'], 0, 50) . '...'
                    ), false);
                }
            }
        }
        $this->output("", false);
    }
    
    /**
     * Display scan summary
     */
    private function displaySummary($results) {
        $total = count($results);
        $clean = 0;
        $infected = 0;
        $errors = 0;
        
        foreach ($results as $result) {
            switch ($result['status']) {
                case 'CLEAN':
                    $clean++;
                    break;
                case 'INFECTED':
                    $infected++;
                    break;
                case 'ERROR':
                    $errors++;
                    break;
            }
        }
        
        $this->output("\n" . str_repeat('=', 50), false);
        $this->output("SCAN SUMMARY", false);
        $this->output(str_repeat('=', 50), false);
        $this->output(sprintf("Total URLs scanned: %d", $total), false);
        $this->output(sprintf("✅ Clean sites: %d", $clean), false);
        $this->output(sprintf("🚨 Infected sites: %d", $infected), false);
        $this->output(sprintf("❌ Errors: %d", $errors), false);
        
        if ($infected > 0) {
            $this->output("\n⚠️  WARNING: Shell threats detected! Review the results immediately.", true);
        } else {
            $this->output("\n✅ All scanned sites appear clean.", false);
        }
    }
    
    /**
     * Save results to JSON file
     */
    private function saveResults($results) {
        $output = [
            'scan_date' => date('Y-m-d H:i:s'),
            'scanner_version' => '1.0',
            'results' => $results
        ];
        
        try {
            file_put_contents($this->options['output'], json_encode($output, JSON_PRETTY_PRINT));
            $this->output("✅ Results saved to: {$this->options['output']}", false);
        } catch (Exception $e) {
            $this->output("❌ Failed to save results: " . $e->getMessage(), true);
        }
    }
    
    /**
     * Output message
     */
    private function output($message, $isError = false) {
        if ($isError) {
            fwrite(STDERR, $message . "\n");
        } else {
            echo $message . "\n";
        }
    }
}

// Check if running from command line
if (php_sapi_name() === 'cli') {
    try {
        $cli = new ScannerCLI();
        $cli->run();
    } catch (Exception $e) {
        echo "Fatal Error: " . $e->getMessage() . "\n";
        exit(1);
    }
} else {
    echo "This script must be run from the command line.\n";
    exit(1);
}

?>