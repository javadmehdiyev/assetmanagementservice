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
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px;
        }
        .header {
            background: rgba(255,255,255,0.95);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 15px;
        }
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .status-online { background: #4CAF50; }
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