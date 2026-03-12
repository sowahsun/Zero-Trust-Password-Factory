<?php
// ===== 🎯 强制禁用缓存 (彻底解决跨设备读取旧数据/无限刷新问题) =====
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

/**
 * ===========================================================================
 * 🔐 Zero-Trust Password Factory (零信任密码工厂)
 * ---------------------------------------------------------------------------
 * 特性：无状态计算、零数据留存、抗社工字典、跨维度隔离
 * ===========================================================================
 */

// ===== 🎯 统一时区设置为上海 =====
date_default_timezone_set('Asia/Shanghai');
mb_internal_encoding('UTF-8');

// ===== 🎯 安全特殊符号配置 =====
$SECURITY_SYMBOLS = [
    'standard' => '!@#$%&*_+-=?',      
    'enhanced' => '!@#$%&*_+-=?:;.,~'  
];

// ===== 🎯 核心逻辑 1：锚点日期标准化 =====
function absoluteDateNormalize($dateInput) {
    $originalTimezone = date_default_timezone_get();
    date_default_timezone_set('Asia/Shanghai');
    
    $dateInput = trim($dateInput);
    
    // 基础 YYYY-MM-DD 验证
    if (preg_match('/^(\d{4})-(\d{1,2})-(\d{1,2})$/', $dateInput, $matches)) {
        if (checkdate((int)$matches[2], (int)$matches[3], (int)$matches[1])) {
            $absolute_date = sprintf('%04d-%02d-%02d', (int)$matches[1], (int)$matches[2], (int)$matches[3]);
            $timestamp = strtotime($absolute_date . ' 00:00:00 Asia/Shanghai');
            date_default_timezone_set($originalTimezone);
            return ['success' => true, 'original_input' => $dateInput, 'absolute_date' => $absolute_date, 'timestamp' => $timestamp];
        }
    }
    
    // 智能提取与正则匹配
    $cleaned = preg_replace('/[^\d\/\-年月日\.]/', '', $dateInput);
    $patterns = [
        '/^(\d{4})[-\.](\d{1,2})[-\.](\d{1,2})$/', '/^(\d{4})[\/](\d{1,2})[\/](\d{1,2})$/', '/^(\d{4})年(\d{1,2})月(\d{1,2})日?$/',
        '/^(\d{1,2})[-\.](\d{1,2})[-\.](\d{4})$/', '/^(\d{1,2})[\/](\d{1,2})[\/](\d{4})$/'
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $cleaned, $matches)) {
            $year = $month = $day = 0;
            if (strlen($matches[1]) === 4) {
                $year = (int)$matches[1]; $month = (int)$matches[2]; $day = (int)$matches[3];
            } else {
                $part1 = (int)$matches[1]; $part2 = (int)$matches[2]; $year = (int)$matches[3];
                if ($part1 > 12 && $part1 <= 31 && $part2 <= 12) { $day = $part1; $month = $part2; } 
                else { $month = $part1; $day = $part2; }
            }
            
            if (checkdate($month, $day, $year)) {
                $absolute_date = sprintf('%04d-%02d-%02d', $year, $month, $day);
                $timestamp = strtotime($absolute_date . ' 00:00:00 Asia/Shanghai');
                date_default_timezone_set($originalTimezone);
                return ['success' => true, 'original_input' => $dateInput, 'absolute_date' => $absolute_date, 'timestamp' => $timestamp];
            }
        }
    }
    
    $timestamp = strtotime($dateInput . ' Asia/Shanghai');
    if ($timestamp !== false) {
        $absolute_date = date('Y-m-d', $timestamp);
        date_default_timezone_set($originalTimezone);
        return ['success' => true, 'original_input' => $dateInput, 'absolute_date' => $absolute_date, 'timestamp' => $timestamp];
    }
    
    date_default_timezone_set($originalTimezone);
    return ['success' => false, 'error' => '无法识别的日期格式'];
}

// ===== 🎯 核心逻辑 2：确定性哈希转换算法 =====
function generateDeterministicValue($hash, $length, $special_chars = '') {
    $hash = strtolower($hash);
    $lowercase = 'abcdefghijklmnopqrstuvwxyz';
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $numbers = '0123456789';
    
    $char_sets = empty($special_chars) ? [$lowercase . $uppercase . $numbers] : [$lowercase, $uppercase, $numbers, $special_chars];
    $value = '';
    $hash_chunks = str_split($hash, 2);
    
    for ($i = 0; $i < $length; $i++) {
        $char_set = $char_sets[$i % count($char_sets)];
        $hash_value = hexdec($hash_chunks[$i % 12]);
        $value .= $char_set[$hash_value % strlen($char_set)];
    }
    return $value;
}

// ===== 🎯 核心逻辑 3：生成多安全级别密码 =====
function generateSmartThreeLevelValues($dateString, $service = '', $personal_key = '') {
    global $SECURITY_SYMBOLS;
    
    $originalTimezone = date_default_timezone_get();
    date_default_timezone_set('Asia/Shanghai');
    
    $normalized = absoluteDateNormalize($dateString);
    if (!$normalized['success']) {
        date_default_timezone_set($originalTimezone);
        return $normalized;
    }
    
    $service = strtolower(trim($service ?? ''));
    $personal_key = trim($personal_key ?? '');
    
    $hash_source = $normalized['absolute_date'];
    if (!empty($service) || !empty($personal_key)) {
        $hash_source .= '_' . (empty($service) ? $personal_key : $service . '_' . $personal_key);
    }
    
    $mode_description = empty($service) && empty($personal_key) ? 'Lv.1 基础模式（仅日期）' : (empty($service) ? 'Lv.2 密钥模式（日期+盐值）' : 'Lv.3 完整模式（日期+用途+盐值）');
    $date_hash = hash('sha256', $hash_source);
    
    $values = [
        'basic' => generateDeterministicValue($date_hash, 12),
        'standard' => generateDeterministicValue($date_hash, 12, $SECURITY_SYMBOLS['standard']), 
        'enhanced' => generateDeterministicValue($date_hash, 16, $SECURITY_SYMBOLS['enhanced'])
    ];
    
    date_default_timezone_set($originalTimezone);
    return ['success' => true, 'original_input' => $normalized['original_input'], 'absolute_date' => $normalized['absolute_date'], 'service' => $service, 'has_personal_key' => !empty($personal_key), 'mode_description' => $mode_description, 'values' => $values];
}

// ===== 🎯 核心逻辑 4：密码有效性逆向比对 =====
function verifyEncodedValue($input_value, $dateString, $service = '', $personal_key = '') {
    $result = generateSmartThreeLevelValues($dateString, $service, $personal_key);
    if (!$result['success']) return ['success' => false, 'error' => '日期解析失败'];
    
    foreach ($result['values'] as $level => $value) {
        if ($input_value === $value) {
            return ['success' => true, 'matched_level' => $level, 'matched_value' => $value, 'date_info' => $result];
        }
    }
    return ['success' => false, 'error' => '输入源与密码哈希值不匹配', 'regenerated_values' => $result['values']];
}

// ===== 🚀 处理请求 API 路由 =====
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    if (isset($_POST['smart_three_level_values'])) {
        echo json_encode(['success' => true, 'result' => generateSmartThreeLevelValues($_POST['date_input'], $_POST['service_input'] ?? '', $_POST['personal_key_input'] ?? '')]);
        exit;
    }

    if (isset($_POST['verify_encoded_value'])) {
        echo json_encode(['success' => true, 'result' => verifyEncodedValue($_POST['verify_value_input'], $_POST['verify_value_date'], $_POST['verify_value_service'] ?? '', $_POST['verify_value_personal_key'] ?? '')]);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>Zero-Trust Password Factory | 零信任密码工厂</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; margin: 0; padding: 20px; background: #f0f2f5; min-height: 100vh; color: #333; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 35px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
        h1, h2, h3 { color: #1a1a1a; text-align: center; margin-bottom: 20px; }
        .section { margin-bottom: 30px; padding-bottom: 25px; border-bottom: 1px solid #ebebeb; }
        .section:last-child { border-bottom: none; }
        
        .info-panel { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 25px; border-left: 5px solid #2c3e50; line-height: 1.6; }
        .mode-indicator { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 13px; margin-right: 8px; background: #e9ecef; color: #495057; border: 1px solid #dee2e6; font-weight: 500;}
        
        .form-group { margin: 18px 0; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #2c3e50; font-size: 14px; }
        .sub-label { font-weight: normal; color: #7f8c8d; font-size: 12px; margin-left: 5px; }
        input { width: 100%; padding: 12px 15px; border: 1px solid #dce1e6; border-radius: 6px; font-size: 15px; transition: border-color 0.2s; }
        input:focus { outline: none; border-color: #3498db; box-shadow: 0 0 0 3px rgba(52,152,219,0.1); }
        
        button { background: #2c3e50; color: white; padding: 14px 30px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; width: 100%; transition: all 0.2s; }
        button:hover { background: #34495e; transform: translateY(-1px); }
        .action-btn { background: #3498db; } .action-btn:hover { background: #2980b9; }
        .verify-btn { background: #16a085; } .verify-btn:hover { background: #1abc9c; }
        
        .results { background: #f8f9fa; padding: 25px; border-radius: 8px; margin-top: 25px; border: 1px solid #e9ecef; display: none; }
        .result-item { padding: 12px; margin: 10px 0; background: white; border-radius: 6px; border-left: 4px solid #3498db; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }
        .loading { display: none; text-align: center; color: #7f8c8d; padding: 20px; font-weight: 500; }
        
        .algorithm-results { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 20px; }
        .algo-result-card { background: white; padding: 20px; border-radius: 8px; border: 1px solid #e0e0e0; box-shadow: 0 2px 5px rgba(0,0,0,0.02); }
        .algo-result-card.success { border-top: 4px solid #3498db; }
        
        .value-level-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: white; float: right; }
        .level-basic { background: #95a5a6; } .level-standard { background: #f39c12; } .level-enhanced { background: #e74c3c; }
        
        .pwd-display { margin: 15px 0; padding: 15px 10px; background: #f8f9fa; text-align: center; font-size: 20px; font-family: 'Consolas', monospace; letter-spacing: 1px; color: #2c3e50; border-radius: 6px; word-break: break-all; }
        .copy-btn { margin-top: 5px; padding: 10px; background: #ecf0f1; color: #2c3e50; font-size: 14px; }
        .copy-btn:hover { background: #bdc3c7; color: #2c3e50; }
        
        .format-hint { font-size: 13px; color: #7f8c8d; margin-top: 6px; min-height: 18px; }
        .format-hint.valid { color: #27ae60; } .format-hint.invalid { color: #e74c3c; }
        
        .verification-success { background: #f0fdf4 !important; border-left-color: #22c55e !important; }
        .verification-fail { background: #fef2f2 !important; border-left-color: #ef4444 !important; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Zero-Trust Password Factory</h1>
        <h3 style="color: #7f8c8d; font-weight: 400; margin-top: -10px; margin-bottom: 30px; font-size: 16px;">真正的无状态加密 · 代码跑线上，暗号记脑中</h3>
        
        <div class="info-panel">
            <strong>🛡️ 核心防御准则：</strong><br>
            • <strong>拒绝自动填充：</strong> 本工具阻断一切浏览器记录，用后即焚。<br>
            • <strong>非对称映射（强烈建议）：</strong> 请使用只有你懂的映射逻辑（如：用途填“买菜”、“吃饭”），彻底废除社工字典的穷举能力。<br>
            • <strong>多级安全产出：</strong><br>
            <div style="margin-top: 10px;">
                <span class="mode-indicator">Lv.1 基础安全</span> 纯字母数字 (12位) - 适用苛刻的老旧系统<br>
                <span class="mode-indicator">Lv.2 标准安全</span> 包含常规符号 (12位) - 适用日常主流网站<br>
                <span class="mode-indicator">Lv.3 增强安全</span> 包含扩展符号 (16位) - 适用核心资产防线
            </div>
        </div>

        <div class="section">
            <h2>🏭 高强度加盐密码生成</h2>
            <form id="generatorForm" onsubmit="return false;">
                <div class="form-group">
                    <label>锚点日期 (Date Anchor) <span class="sub-label">可以自己写一个你能记住的日期，作为你的绝对时间维度</span></label>
                    <div style="display: flex; gap: 10px;">
                        <input type="text" id="smartDateInput" placeholder="例如：1983-11-24 (任何你能记住的日子)" style="flex: 1;" required autocomplete="off" readonly onfocus="this.removeAttribute('readonly')">
                        <button type="button" onclick="setDateVal('smartDateInput', 'today')" style="width: auto; background: #ecf0f1; color: #2c3e50; padding: 0 15px;">当天日期</button>
                        <button type="button" onclick="setDateVal('smartDateInput', 'random')" style="width: auto; background: #2c3e50; color: #fff; padding: 0 15px;">🎲 随机日期</button>
                    </div>
                    <div class="format-hint" id="smartDateInputHint"></div>
                </div>
                
                <div class="form-group">
                    <label>用途映射 (Service Mapping) <span class="sub-label">建议填写非关联暗号，例如“买菜”</span></label>
                    <input type="text" id="serviceInput" placeholder="选填（留空则生成全站通用密码）" autocomplete="off" readonly onfocus="this.removeAttribute('readonly')">
                </div>
                
                <div class="form-group">
                    <label>私有盐值 (Private Salt) <span class="sub-label">存在你大脑里的终极防线密钥</span></label>
                    <input type="text" id="personalKeyInput" placeholder="强烈建议填写" autocomplete="off" readonly onfocus="this.removeAttribute('readonly')">
                </div>
                
                <button type="submit" class="action-btn" id="generateBtn" style="margin-top: 10px;">执行哈希计算生成密码</button>
            </form>
            <div class="loading" id="generateLoading">算法正在运行，请稍候...</div>
            <div class="results" id="generateResults"></div>
        </div>
        
        <div class="section" style="padding-top: 10px;">
            <h2>✅ 密码有效性校验</h2>
            <p style="text-align: center; color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">逆向核对你的输入源是否能成功推导出当前密码</p>
            <form id="verifyForm" onsubmit="return false;">
                <div class="form-group">
                    <label>输入待校验密码 (Password Hash)</label>
                    <input type="text" id="verifyValueInput" required autocomplete="off" readonly onfocus="this.removeAttribute('readonly')" placeholder="粘贴你生成的密码">
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px;">
                    <div class="form-group">
                        <label>锚点日期</label>
                        <input type="text" id="verifyValueDate" required autocomplete="off" readonly onfocus="this.removeAttribute('readonly')">
                    </div>
                    <div class="form-group">
                        <label>用途映射</label>
                        <input type="text" id="verifyValueService" autocomplete="off" readonly onfocus="this.removeAttribute('readonly')">
                    </div>
                    <div class="form-group">
                        <label>私有盐值</label>
                        <input type="text" id="verifyValuePersonalKey" autocomplete="off" readonly onfocus="this.removeAttribute('readonly')">
                    </div>
                </div>
                <button type="submit" class="verify-btn" id="verifyBtn">校验一致性</button>
            </form>
            <div class="loading" id="verifyValueLoading">正在校验指纹，请稍候...</div>
            <div class="results" id="verifyValueResults"></div>
        </div>
    </div>

    <script>
        // --- 核心网络请求封装 (动态时间戳，打破浏览器缓存) ---
        function apiRequest(dataObj, loadingId, resultsId, onSuccess) {
            const loading = document.getElementById(loadingId);
            const results = document.getElementById(resultsId);
            
            if(loading) loading.style.display = 'block';
            if(results) results.style.display = 'none';
            
            const formData = new FormData();
            for (const key in dataObj) formData.append(key, dataObj[key]);
            
            fetch('?_t=' + new Date().getTime(), { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    if(loading) loading.style.display = 'none';
                    onSuccess(data);
                }).catch(() => {
                    if(loading) loading.style.display = 'none';
                    alert('网络通讯异常，计算请求未送达服务器。');
                });
        }

        // --- 辅助工具函数 ---
        function setDateVal(inputId, date) {
            let finalDate = date;
            
            if (date === 'today') {
                // 纯本地时间，无视时区强转干扰
                const d = new Date();
                const yyyy = d.getFullYear();
                const mm = String(d.getMonth() + 1).padStart(2, '0');
                const dd = String(d.getDate()).padStart(2, '0');
                finalDate = `${yyyy}-${mm}-${dd}`;
            } 
            else if (date === 'random') {
                // 🎲 生成 1970年 到 2050年 之间的绝对随机日期
                const start = new Date(1970, 0, 1).getTime();
                const end = new Date(2050, 11, 31).getTime();
                const randomTime = new Date(start + Math.random() * (end - start));
                const yyyy = randomTime.getFullYear();
                const mm = String(randomTime.getMonth() + 1).padStart(2, '0');
                const dd = String(randomTime.getDate()).padStart(2, '0');
                finalDate = `${yyyy}-${mm}-${dd}`;
            }

            document.getElementById(inputId).value = finalDate;
            document.getElementById(inputId).dispatchEvent(new Event('input'));
        }

        function updateHint(inputId, hintId, actionKey) {
            const input = document.getElementById(inputId).value;
            const hint = document.getElementById(hintId);
            if (!input) { hint.textContent = ''; hint.className = 'format-hint'; return; }
            
            // 复用后端的验证路由进行静默检测
            apiRequest({ smart_three_level_values: 1, date_input: input }, null, null, data => {
                if (data.success && data.result && data.result.success) {
                    hint.textContent = `系统识别标准化日期: ${data.result.absolute_date}`;
                    hint.className = 'format-hint valid';
                } else {
                    hint.textContent = '警告：无效的日期格式';
                    hint.className = 'format-hint invalid';
                }
            });
        }

        function copyToClipboard(text, btn) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select(); document.execCommand('copy');
            document.body.removeChild(textArea);
            const original = btn.innerHTML;
            btn.innerHTML = '✅ 已成功复制至剪贴板';
            btn.style.background = '#27ae60';
            btn.style.color = '#fff';
            setTimeout(() => { 
                btn.innerHTML = original; 
                btn.style.background = ''; 
                btn.style.color = ''; 
            }, 2000);
        }

        function getCharTypes(val) {
            return [/[a-z]/.test(val) ? '小写' : '', /[A-Z]/.test(val) ? '大写' : '', /[0-9]/.test(val) ? '数字' : '', /[^a-zA-Z0-9]/.test(val) ? '特殊符号' : ''].filter(Boolean).join(' + ');
        }

        // --- 事件监听 ---
        document.getElementById('smartDateInput').addEventListener('input', () => updateHint('smartDateInput', 'smartDateInputHint', 'smart_three_level_values'));

        // 密码生成提交
        document.getElementById('generateBtn').addEventListener('click', e => {
            e.preventDefault();
            if(!document.getElementById('smartDateInput').value) return alert('请填入锚点日期作为计算基准。');
            
            apiRequest({ 
                smart_three_level_values: 1, 
                date_input: document.getElementById('smartDateInput').value, 
                service_input: document.getElementById('serviceInput').value, 
                personal_key_input: document.getElementById('personalKeyInput').value 
            }, 'generateLoading', 'generateResults', data => {
                const r = data.result;
                const badges = { 
                    basic: ['level-basic', 'Lv.1 基础安全'], 
                    standard: ['level-standard', 'Lv.2 标准安全'], 
                    enhanced: ['level-enhanced', 'Lv.3 增强安全'] 
                };
                
                let html = '<h3>哈希计算结果</h3>' + (!r.success ? `<div class="result-item" style="border-left-color:#e74c3c;">${r.error}</div>` : 
                    `<div class="result-item"><strong>基准日期：</strong>${r.absolute_date}<br><strong>作用域：</strong>${r.mode_description}</div>
                     <div class="algorithm-results">` +
                    Object.entries(r.values).map(([k, v]) => `
                        <div class="algo-result-card success">
                            <div style="margin-bottom: 10px;">
                                <span class="value-level-badge ${badges[k][0]}">${badges[k][1]}</span>
                                <span style="font-size: 14px; font-weight: 600; color: #34495e;">${k === 'basic' ? '12位纯字母数字' : (k === 'standard' ? '12位含常规符号' : '16位扩展高强度')}</span>
                            </div>
                            <div class="pwd-display">${v}</div>
                            <div style="font-size:12px;color:#7f8c8d;text-align:center;margin-bottom:10px;">特征包含：${getCharTypes(v)}</div>
                            <button type="button" class="copy-btn" onclick="copyToClipboard('${v}', this)" style="width:100%; border:none; cursor:pointer; border-radius:4px;">📋 复制此密码</button>
                        </div>`).join('') + '</div>');
                
                const res = document.getElementById('generateResults'); 
                res.innerHTML = html; 
                res.style.display = 'block';
            });
        });

        // 密码校验提交
        document.getElementById('verifyBtn').addEventListener('click', e => {
            e.preventDefault();
            const val = document.getElementById('verifyValueInput').value;
            const dt = document.getElementById('verifyValueDate').value;
            if(!val || !dt) return alert('请确保已填入【待校验密码】及对应的【锚点日期】。');
            
            apiRequest({ 
                verify_encoded_value: 1, 
                verify_value_input: val, 
                verify_value_date: dt, 
                verify_value_service: document.getElementById('verifyValueService').value, 
                verify_value_personal_key: document.getElementById('verifyValuePersonalKey').value 
            }, 'verifyValueLoading', 'verifyValueResults', data => {
                if(!data || !data.result) return;
                const r = data.result;
                const names = { basic: 'Lv.1 基础安全密码', standard: 'Lv.2 标准安全密码', enhanced: 'Lv.3 增强安全密码' };
                
                let html = r.success ? 
                    `<div class="result-item verification-success">
                        <h4 style="margin-top:0; color:#166534;">✅ 校验通过 (Valid Match)</h4>
                        <strong>安全级别：</strong>${names[r.matched_level]}<br>
                        <strong>溯源日期：</strong>${r.date_info.absolute_date}<br>
                        <strong>所属域：</strong>${r.date_info.mode_description}
                    </div>` : 
                    `<div class="result-item verification-fail">
                        <h4 style="margin-top:0; color:#991b1b;">❌ 校验驳回 (Invalid Match)</h4>
                        <strong>失败诊断：</strong>当前提供的原始信息经过哈希运算后，无法生成你填入的密码值。<hr style="border:0; border-top:1px dashed #fca5a5; margin: 10px 0;">
                        <strong>当前输入源推导出的正确值为：</strong><br>` + 
                        Object.entries(r.regenerated_values||{}).map(([k,v])=>`<span style="color:#7f8c8d;">• ${names[k]}:</span> <code style="color:#e74c3c;">${v}</code>`).join('<br>') + 
                    `</div>`;
                
                const res = document.getElementById('verifyValueResults'); 
                res.innerHTML = html; 
                res.style.display = 'block';
            });
        });
    </script>
</body>
</html>
