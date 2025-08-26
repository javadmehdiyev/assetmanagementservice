<?php
header('Content-Type: text/html; charset=utf-8');

// Configuration
$assetsFile = 'assets.json';
$configFile = 'config.json';

// Read assets data
function getAssets($file) {
    if (!file_exists($file)) {
        return ['error' => 'Assets file not found. Run the daemon first.'];
    }
    
    $data = file_get_contents($file);
    $json = json_decode($data, true);
    
    if ($json === null) {
        return ['error' => 'Invalid JSON in assets file'];
    }
    
    return $json;
}

// Read config data
function getConfig($file) {
    if (!file_exists($file)) {
        return ['service' => ['name' => 'Asset Management Service']];
    }
    
    $data = file_get_contents($file);
    $json = json_decode($data, true);
    
    return $json ?: ['service' => ['name' => 'Asset Management Service']];
}

// Get system status
function getSystemStatus() {
    $processes = shell_exec('ps aux | grep -v grep | grep asset-daemon | wc -l');
    return (int)trim($processes) > 0;
}

// Get file age
function getFileAge($file) {
    if (!file_exists($file)) return 'Unknown';
    
    $age = time() - filemtime($file);
    if ($age < 60) return $age . ' seconds ago';
    if ($age < 3600) return floor($age/60) . ' minutes ago';
    if ($age < 86400) return floor($age/3600) . ' hours ago';
    return floor($age/86400) . ' days ago';
}

// Helper function to format OS badge
function getOSBadge($deviceInfo) {
    if (!$deviceInfo || !isset($deviceInfo['os_family'])) return '';
    
    $os = $deviceInfo['os_family'];
    
    $badges = [
        'iOS' => ['🍎', '#007AFF'],
        'macOS' => ['💻', '#007AFF'],
        'Windows' => ['🪟', '#0078D4'],
        'Linux' => ['🐧', '#FCC624'],
        'Android' => ['🤖', '#3DDC84'],
        'FreeBSD' => ['😈', '#AB2B28'],
        'Unix' => ['⚙️', '#25283D']
    ];
    
    $badge = $badges[$os] ?? ['❓', '#6C757D'];
    return "<span class='os-badge' style='background-color: {$badge[1]}'>{$badge[0]} {$os}</span>";
}

// Helper function to get device type icon
function getDeviceTypeIcon($deviceInfo) {
    if (!$deviceInfo || !isset($deviceInfo['device_type'])) return '❓';
    
    $icons = [
        'mobile' => '📱',
        'computer' => '💻',
        'server' => '🖥️',
        'router' => '📡',
        'switch' => '🔀',
        'printer' => '🖨️',
        'media_device' => '📺',
        'iot' => '🏠'
    ];
    
    return $icons[$deviceInfo['device_type']] ?? '❓';
}

// Helper function to get vulnerability status
function getVulnerabilityBadge($asset) {
    $vulnCount = 0;
    $vulnTypes = [];
    
    if (isset($asset['has_default_creds']) && $asset['has_default_creds']) {
        $vulnCount++;
        $vulnTypes[] = 'Default Credentials';
    }
    
    if (isset($asset['credential_results'])) {
        $credVulns = count($asset['credential_results']);
        if ($credVulns > 0) {
            $vulnTypes[] = "{$credVulns} Credential Issues";
        }
    }
    
    if ($vulnCount > 0) {
        return "<span class='vuln-badge vuln-high'>🚨 {$vulnCount} Issues</span>";
    }
    
    return "<span class='vuln-badge vuln-safe'>✅ Safe</span>";
}

$assets = getAssets($assetsFile);
$config = getConfig($configFile);
$daemonRunning = getSystemStatus();
$lastUpdate = getFileAge($assetsFile);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($config['service']['name'] ?? 'Asset Management') ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 20px;
        }
        .header {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            backdrop-filter: blur(10px);
        }
        .status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        .status-item {
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(255,255,255,0.7);
            padding: 8px 15px;
            border-radius: 20px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .status-online { background: #4CAF50; }
        .status-offline { background: #f44336; }
        
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.7; }
            100% { transform: scale(1); opacity: 1; }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.95);
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .asset-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .asset-card {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            backdrop-filter: blur(10px);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .asset-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
        }
        
        .asset-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .asset-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.2em;
            font-weight: bold;
        }
        
        .asset-ip {
            font-family: 'Courier New', monospace;
            background: #667eea;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        
        .device-info {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .device-row {
            display: flex;
            justify-content: space-between;
            margin: 5px 0;
        }
        
        .os-badge {
            color: white;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .vuln-badge {
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .vuln-high {
            background: #f44336;
            color: white;
        }
        
        .vuln-safe {
            background: #4CAF50;
            color: white;
        }
        
        .ports-section {
            margin: 15px 0;
        }
        
        .port-item {
            display: inline-block;
            background: linear-gradient(45deg, #4CAF50, #45a049);
            color: white;
            padding: 6px 12px;
            border-radius: 20px;
            margin: 3px;
            font-size: 0.85em;
            font-weight: bold;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        
        .credentials-section {
            background: #ffebee;
            border: 2px solid #f44336;
            border-radius: 10px;
            padding: 10px;
            margin: 10px 0;
        }
        
        .credential-item {
            background: #f44336;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            margin: 3px;
            display: inline-block;
            font-size: 0.8em;
        }
        
        .screenshots-section {
            margin: 15px 0;
        }
        
        .screenshot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }
        
        .screenshot-item {
            text-align: center;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 8px;
        }
        
        .screenshot-item img {
            max-width: 100%;
            border-radius: 5px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .services-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin: 10px 0;
            font-size: 0.9em;
        }
        
        .service-item {
            background: #e3f2fd;
            padding: 8px;
            border-radius: 8px;
            border-left: 4px solid #2196F3;
        }
        
        .error {
            background: #f44336;
            color: white;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            font-size: 1.1em;
        }
        
        .refresh-btn {
            background: linear-gradient(45deg, #2196F3, #1976D2);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            box-shadow: 0 4px 15px rgba(33, 150, 243, 0.3);
            transition: all 0.3s ease;
        }
        
        .refresh-btn:hover {
            background: linear-gradient(45deg, #1976D2, #1565C0);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(33, 150, 243, 0.4);
        }
        
        .filter-section {
            background: rgba(255,255,255,0.95);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-btn {
            padding: 8px 16px;
            border: 2px solid #667eea;
            background: transparent;
            color: #667eea;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
                </div>

        <?php if (isset($assets['error'])): ?>
            <div class="error">
                ❌ <?= htmlspecialchars($assets['error']) ?>
            </div>
        <?php else: ?>
            <?php 
            $assetList = $assets['assets'] ?? [];
            $totalAssets = count($assetList);
            $vulnAssets = 0;
            $osTypes = [];
            $totalPorts = 0;
            $totalCredentialIssues = 0;
            
            foreach ($assetList as $asset) {
                if (isset($asset['has_default_creds']) && $asset['has_default_creds']) {
                    $vulnAssets++;
                }
                if (isset($asset['device_info']['os_family'])) {
                    $os = $asset['device_info']['os_family'];
                    $osTypes[$os] = ($osTypes[$os] ?? 0) + 1;
                }
                if (isset($asset['open_ports'])) {
                    $totalPorts += count($asset['open_ports']);
                }
                if (isset($asset['credential_results'])) {
                    $totalCredentialIssues += count($asset['credential_results']);
                }
            }
            ?>
            
            <!-- Statistics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number"><?= $totalAssets ?></div>
                    <div>Total Assets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?= $vulnAssets ?></div>
                    <div>Vulnerable Assets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?= $totalPorts ?></div>
                    <div>Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?= $totalCredentialIssues ?></div>
                    <div>Credential Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?= count($osTypes) ?></div>
                    <div>OS Types</div>
                </div>
            </div>

            <!-- Filter Section -->
            <div class="filter-section">
                <strong>Filter by:</strong>
                <button class="filter-btn active" onclick="filterAssets('all')">🌐 All</button>
                <button class="filter-btn" onclick="filterAssets('vulnerable')">🚨 Vulnerable</button>
                <button class="filter-btn" onclick="filterAssets('apple')">🍎 Apple</button>
                <button class="filter-btn" onclick="filterAssets('windows')">🪟 Windows</button>
                <button class="filter-btn" onclick="filterAssets('linux')">🐧 Linux</button>
                <button class="filter-btn" onclick="filterAssets('mobile')">📱 Mobile</button>
            </div>

            <!-- Assets Grid -->
            <div class="asset-grid">
                <?php if (empty($assetList)): ?>
                    <div class="error">
                        🔍 No assets found. Make sure the daemon is running and has completed at least one scan.
                    </div>
                <?php else: ?>
                    <?php foreach ($assetList as $asset): ?>
                        <?php
                        $deviceInfo = $asset['device_info'] ?? null;
                        $hostname = $asset['hostname'] ?? 'Unknown';
                        $manufacturer = $deviceInfo['manufacturer'] ?? '';
                        $osFamily = $deviceInfo['os_family'] ?? '';
                        $deviceType = $deviceInfo['device_type'] ?? '';
                        $isVulnerable = (isset($asset['has_default_creds']) && $asset['has_default_creds']) || 
                                       (isset($asset['credential_results']) && count($asset['credential_results']) > 0);
                        
                        // Create filter classes
                        $filterClasses = ['asset-card'];
                        if ($isVulnerable) $filterClasses[] = 'filter-vulnerable';
                        if (stripos($osFamily, 'iOS') !== false || stripos($osFamily, 'macOS') !== false || $manufacturer === 'Apple') $filterClasses[] = 'filter-apple';
                        if (stripos($osFamily, 'Windows') !== false) $filterClasses[] = 'filter-windows';
                        if (stripos($osFamily, 'Linux') !== false) $filterClasses[] = 'filter-linux';
                        if ($deviceType === 'mobile') $filterClasses[] = 'filter-mobile';
                        ?>
                        
                        <div class="<?= implode(' ', $filterClasses) ?>">
                            <!-- Asset Header -->
                            <div class="asset-header">
                                <div class="asset-title">
                                    <span style="font-size: 1.5em;"><?= getDeviceTypeIcon($deviceInfo) ?></span>
                                    <div>
                                        <div><?= htmlspecialchars($hostname) ?></div>
                                        <div class="asset-ip"><?= htmlspecialchars($asset['ip']) ?></div>
                                    </div>
                                </div>
                                <?= getVulnerabilityBadge($asset) ?>
                            </div>

                            <!-- Device Information -->
                            <?php if ($deviceInfo): ?>
                            <div class="device-info">
                                <h3>🔍 Device Information</h3>
                                <?php if ($osFamily): ?>
                                <div class="device-row">
                                    <strong>Operating System:</strong>
                                    <?= getOSBadge($deviceInfo) ?>
                                    <?php if (isset($deviceInfo['os_version']) && $deviceInfo['os_version']): ?>
                                        <span style="margin-left: 10px; color: #666;"><?= htmlspecialchars($deviceInfo['os_version']) ?></span>
                                    <?php endif; ?>
                                </div>
                                <?php endif; ?>
                                
                                <?php if ($manufacturer): ?>
                                <div class="device-row">
                                    <strong>Manufacturer:</strong>
                                    <span><?= htmlspecialchars($manufacturer) ?></span>
                                </div>
                                <?php endif; ?>
                                
                                <?php if ($deviceType): ?>
                                <div class="device-row">
                                    <strong>Device Type:</strong>
                                    <span><?= htmlspecialchars(ucfirst($deviceType)) ?></span>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (isset($deviceInfo['detection_methods']) && !empty($deviceInfo['detection_methods'])): ?>
                                <div class="device-row">
                                    <strong>Detection Methods:</strong>
                                    <span style="font-size: 0.9em; color: #666;"><?= implode(', ', $deviceInfo['detection_methods']) ?></span>
                                </div>
                                <?php endif; ?>
                            </div>
                            <?php endif; ?>

                            <!-- Network Information -->
                            <div class="device-info">
                                <h3>🌐 Network Information</h3>
                                <?php if (isset($asset['mac']) && $asset['mac']): ?>
                                <div class="device-row">
                                    <strong>MAC Address:</strong>
                                    <span style="font-family: monospace;"><?= htmlspecialchars($asset['mac']) ?></span>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (isset($asset['vendor']) && $asset['vendor']): ?>
                                <div class="device-row">
                                    <strong>MAC Vendor:</strong>
                                    <span><?= htmlspecialchars($asset['vendor']) ?></span>
                                </div>
                                <?php endif; ?>
                                
                                <div class="device-row">
                                    <strong>ARP Response:</strong>
                                    <span><?= isset($asset['arp_response']) && $asset['arp_response'] ? '✅ Yes' : '❌ No' ?></span>
                                </div>
                            </div>

                            <!-- Open Ports -->
                            <?php if (isset($asset['open_ports']) && !empty($asset['open_ports'])): ?>
                            <div class="ports-section">
                                <h3>🔓 Open Ports (<?= count($asset['open_ports']) ?>)</h3>
                                <?php foreach ($asset['open_ports'] as $port): ?>
                                    <span class="port-item">
                                        <?= htmlspecialchars($port['port']) ?><?= isset($port['service']) ? '/' . htmlspecialchars($port['service']) : '' ?>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>

                            <!-- Credential Issues -->
                            <?php if (isset($asset['credential_results']) && !empty($asset['credential_results'])): ?>
                            <div class="credentials-section">
                                <h3>🚨 Credential Vulnerabilities</h3>
                                <p style="margin-bottom: 10px; color: #d32f2f;"><strong>⚠️ Default credentials found!</strong></p>
                                <?php foreach ($asset['credential_results'] as $cred): ?>
                                    <span class="credential-item">
                                        <?= htmlspecialchars($cred['service']) ?>:<?= htmlspecialchars($cred['port']) ?> 
                                        → <?= htmlspecialchars($cred['username']) ?>:<?= htmlspecialchars($cred['password']) ?>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>

                            <!-- Screenshots -->
                            <?php if (isset($asset['screenshot_results']) && !empty($asset['screenshot_results'])): ?>
                            <div class="screenshots-section">
                                <h3>📸 Web Interface Screenshots</h3>
                                <div class="screenshot-grid">
                                    <?php foreach ($asset['screenshot_results'] as $screenshot): ?>
                                        <div class="screenshot-item">
                                            <img src="<?= htmlspecialchars($screenshot['file_path']) ?>" 
                                                 alt="Screenshot of <?= htmlspecialchars($screenshot['url']) ?>"
                                                 style="max-height: 200px; cursor: pointer;"
                                                 onclick="window.open(this.src, '_blank')">
                                            <div style="margin-top: 5px; font-size: 0.8em;">
                                                <a href="<?= htmlspecialchars($screenshot['url']) ?>" target="_blank">
                                                    <?= htmlspecialchars($screenshot['url']) ?>
                                                </a>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <?php endif; ?>

                            <!-- Services Information -->
                            <?php if (isset($deviceInfo['services']) && !empty($deviceInfo['services'])): ?>
                            <div class="device-info">
                                <h3>🔧 Detected Services</h3>
                                <div class="services-grid">
                                    <?php foreach ($deviceInfo['services'] as $service => $value): ?>
                                        <div class="service-item">
                                            <strong><?= htmlspecialchars(ucfirst(str_replace('_', ' ', $service))) ?>:</strong>
                                            <span><?= htmlspecialchars($value) ?></span>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <?php endif; ?>

                            <!-- Timestamps -->
                            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee; font-size: 0.9em; color: #666;">
                                <?php if (isset($asset['first_seen'])): ?>
                                    <div><strong>First Seen:</strong> <?= date('Y-m-d H:i:s', strtotime($asset['first_seen'])) ?></div>
                                <?php endif; ?>
                                <?php if (isset($asset['last_seen'])): ?>
                                    <div><strong>Last Seen:</strong> <?= date('Y-m-d H:i:s', strtotime($asset['last_seen'])) ?></div>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function filterAssets(type) {
            // Remove active class from all buttons
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            
            // Add active class to clicked button
            event.target.classList.add('active');
            
            // Show all assets first
            document.querySelectorAll('.asset-card').forEach(card => {
                card.style.display = 'block';
            });
            
            // Apply filter
            if (type !== 'all') {
                document.querySelectorAll('.asset-card').forEach(card => {
                    if (!card.classList.contains(`filter-${type}`)) {
                        card.style.display = 'none';
                    }
                });
            }
        }
        
        // Auto-refresh every 30 seconds
        setTimeout(() => {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🚀 <?= htmlspecialchars($config['service']['name'] ?? 'Asset Management Service') ?></h1>
            <div class="status">
                <div class="status-item">
                    <div class="status-dot <?= $daemonRunning ? 'status-online' : 'status-offline' ?>"></div>
                    <span><strong>Daemon:</strong> <?= $daemonRunning ? 'Running' : 'Stopped' ?></span>
                </div>
                <div class="status-item">
                    <span><strong>Last Update:</strong> <?= $lastUpdate ?></span>
                </div>
                <div class="status-item">
                    <span><strong>Scan Time:</strong> <?= isset($assets['scan_time']) ? $assets['scan_time'] : 'Unknown' ?></span>
                </div>
                <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
            </div>
        </div>
        .status-offline { background: #f44336; }
        .stats {
            background: rgba(255,255,255,0.95);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            border-radius: 8px;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            display: block;
        }
        .assets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        .asset-card {
            background: rgba(255,255,255,0.95);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .asset-card:hover {
            transform: translateY(-2px);
        }
        .asset-ip {
            font-size: 1.2em;
            font-weight: bold;
            color: #2196F3;
            margin-bottom: 10px;
        }
        .asset-info {
            margin-bottom: 10px;
        }
        .asset-info span {
            font-weight: bold;
        }
        .ports {
            margin-top: 15px;
        }
        .port-item {
            display: inline-block;
            background: #4CAF50;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            margin: 2px;
            font-size: 0.9em;
        }
        .error {
            background: #f44336;
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .refresh-btn {
            background: #2196F3;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
        }
        .refresh-btn:hover {
            background: #1976D2;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🚀 <?= htmlspecialchars($config['service']['name'] ?? 'Asset Management Service') ?></h1>
            <div class="status">
                <div class="status-item">
                    <div class="status-dot <?= $daemonRunning ? 'status-online' : 'status-offline' ?>"></div>
                    <span>Daemon: <?= $daemonRunning ? 'Running' : 'Stopped' ?></span>
                </div>
                <div class="status-item">
                    <span>Last Update: <?= $lastUpdate ?></span>
                </div>
                <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
            </div>
        </div>

        <?php if (isset($assets['error'])): ?>
            <!-- Error Message -->
            <div class="error">
                ❌ <?= htmlspecialchars($assets['error']) ?>
            </div>
        <?php else: ?>
            <!-- Statistics -->
            <div class="stats">
                <div class="stat-item">
                    <span class="stat-number"><?= $assets['total_hosts'] ?? 0 ?></span>
                    <span>Total Hosts</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number"><?= $assets['file_targets'] ?? 0 ?></span>
                    <span>File Targets</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number"><?= $assets['scan_time'] ?? 'N/A' ?></span>
                    <span>Scan Time</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number"><?= htmlspecialchars($assets['local_network'] ?? 'N/A') ?></span>
                    <span>Local Network</span>
                </div>
            </div>

            <!-- Assets Grid -->
            <div class="assets-grid">
                <?php if (isset($assets['assets']) && is_array($assets['assets'])): ?>
                    <?php foreach ($assets['assets'] as $asset): ?>
                        <div class="asset-card">
                            <div class="asset-ip">📡 <?= htmlspecialchars($asset['ip']) ?></div>
                            
                            <?php if (!empty($asset['hostname'])): ?>
                            <div class="asset-info">
                                <span>Hostname:</span> <?= htmlspecialchars($asset['hostname']) ?>
                            </div>
                            <?php endif; ?>
                            
                            <?php if (!empty($asset['mac'])): ?>
                            <div class="asset-info">
                                <span>MAC:</span> <?= htmlspecialchars($asset['mac']) ?>
                            </div>
                            <?php endif; ?>
                            
                            <?php if (!empty($asset['vendor'])): ?>
                            <div class="asset-info">
                                <span>Vendor:</span> <?= htmlspecialchars($asset['vendor']) ?>
                            </div>
                            <?php endif; ?>
                            
                            <div class="asset-info">
                                <span>Method:</span> <?= htmlspecialchars($asset['discovery_method'] ?? 'Unknown') ?>
                            </div>
                            
                            <?php if (!empty($asset['open_ports'])): ?>
                            <div class="ports">
                                <strong>Open Ports:</strong><br>
                                <?php foreach ($asset['open_ports'] as $port): ?>
                                    <span class="port-item">
                                        <?= $port['port'] ?>/<?= htmlspecialchars($port['protocol'] ?? 'tcp') ?>
                                        <?php if (!empty($port['service'])): ?>
                                            (<?= htmlspecialchars($port['service']) ?>)
                                        <?php endif; ?>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                            <?php endif; ?>
                            
                            <?php if (!empty($asset['last_seen'])): ?>
                            <div class="asset-info" style="margin-top: 10px; font-size: 0.9em; color: #666;">
                                <span>Last Seen:</span> <?= date('Y-m-d H:i:s', strtotime($asset['last_seen'])) ?>
                            </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div style="grid-column: 1/-1; text-align: center; padding: 40px;">
                        <h3>No assets found</h3>
                        <p>Start the daemon to discover network assets.</p>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- Footer -->
        <div style="text-align: center; margin-top: 40px; color: rgba(255,255,255,0.7);">
            <p>Scan Timestamp: <?= htmlspecialchars($assets['timestamp'] ?? 'Never') ?></p>
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds if daemon is running
        <?php if ($daemonRunning): ?>
        setTimeout(() => location.reload(), 30000);
        <?php endif; ?>
    </script>
</body>
</html> 