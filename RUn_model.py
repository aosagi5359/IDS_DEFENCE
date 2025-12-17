import time
import logging
import logging.handlers
import numpy as np
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP, conf, rdpcap, wrpcap
import pandas as pd
import joblib
from datetime import datetime
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import threading
import winreg
import psutil
from concurrent.futures import ThreadPoolExecutor
import socket
import random
import subprocess
from binascii import hexlify
import ipaddress
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import matplotlib
import queue
# Flood 保護相關全域變數（會被設定覆蓋）
FLOOD_PROTECTION_ENABLED = True
FLOOD_QUEUE_HIGH = 4500      # 佇列大於此值啟動丟包
FLOOD_QUEUE_LOW = 800        # 佇列小於此值恢復正常
FLOOD_KEEP_RATIO = 0.02      # Flood 時保留比例（2%）
packet_queue = queue.Queue(maxsize=6000)
matplotlib.rcParams['font.family'] = 'Noto Sans TC'
matplotlib.rcParams['font.sans-serif'] = ['Noto Sans TC']
matplotlib.rcParams['axes.unicode_minus'] = False
# 確保日誌目錄存在
LOG_DIR = 'C:/IDS_defense/logs'
dropped_packets    = 0
DROP_MODE          = False
displayed_this_sec = 0
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger(__name__)
    logger.debug(f"日誌目錄已創建或存在：{LOG_DIR}")
except Exception as e:
    print(f"無法創建日誌目錄 {LOG_DIR}：{str(e)}")
    logger = logging.getLogger(__name__)
    logger.warning(f"無法創建日誌目錄 {LOG_DIR}：{str(e)}，改用控制台日誌")
# 配置主日誌
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(LOG_DIR, 'realtime_detection.log')),
            logging.StreamHandler()
        ]
    )
    logger.debug("主日誌配置成功")
except Exception as e:
    logger.error(f"無法配置主日誌：{str(e)}")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
# JSON 配置文件
CONFIG_FILE = 'C:/IDS_defense/config.json'
# 執行緒鎖
lock = threading.Lock()
# 新增：白名單端口和自動封鎖變數
whitelist_ports = []
auto_block_ports = True # 預設啟用自動封鎖
# 新增：日志統計
log_stats = {'total': 0, 'warning': 0, 'top_types': Counter()}
# 新增：模型選擇和更新
available_models = {'xgboost': 'C:\\IDS_defense\\models\\xgboost_model.pkl', 'rf': 'C:\\IDS_defense\\models\\rf_model.pkl'} # 假設有 RF 模型
current_model = 'xgboost'
# ==================== 響應式字體 & 按鍵大小（自動隨視窗縮放） ====================
import tkinter.font as tkfont

# 全域字體基準（會隨著視窗寬度自動調整）
BASE_FONT_SIZE = 10
BUTTON_PADDING_Y = 8
BUTTON_PADDING_X = 12
# ==================== 危險日誌 logger 安全初始化 ====================
hazard_logger = logging.getLogger('HazardLogger')
hazard_logger.setLevel(logging.WARNING)
hazard_logger.propagate = False  # 避免重複輸出到 root logger

# 先加一個保險的 StreamHandler，確保 logger 永遠能輸出（即使檔案失敗）
fallback_handler = logging.StreamHandler()
fallback_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
hazard_logger.addHandler(fallback_handler)

# ==================== 改為每日輪替的 hazard 日誌 ====================
def setup_hazard_logger():
    """每天產生一個新的 hazard 日誌檔案，並確保 handler 永遠有效"""
    global hazard_logger, hazard_log_file
    
    # 移除舊的 handlers（避免重複添加）
    if hazard_logger:
        hazard_logger.handlers.clear()
    
    # 每日新檔名
    today = datetime.now().strftime("%Y%m%d")
    hazard_log_file = os.path.join(LOG_DIR, f'hazard_{today}.log')
    
    hazard_logger = logging.getLogger('HazardLogger')
    hazard_logger.setLevel(logging.WARNING)
    hazard_logger.propagate = False  # 防止傳到 root logger
    
    # 每天一個檔案，手動控制（比 Rotating 更可靠）
    file_handler = logging.FileHandler(hazard_log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    hazard_logger.addHandler(file_handler)
    
    logger.info(f"危險日誌已重新配置：{hazard_log_file}")

# 程式啟動時呼叫一次
setup_hazard_logger()

# 每天午夜自動切換新檔案（加入 periodic_cleanup）
def periodic_cleanup(self):
    clean_flow_state(self.flow_state)
    # backup_hazard_log()  # 可保留備份舊檔
    # 每天檢查是否需要切新 hazard 檔
    today = datetime.now().strftime("%Y%m%d")
    current_hazard_file = os.path.join(LOG_DIR, f'hazard_{today}.log')
    global hazard_log_file
    if hazard_log_file != current_hazard_file:
        setup_hazard_logger()  # 切換新檔
    self.root.after(60000, self.periodic_cleanup)  # 改為每分鐘檢查一次

class ResponsiveDesign:
    def __init__(self, root):
        self.root = root
        self.current_scale = 1.0
        self.default_font = tkfont.nametofont("TkDefaultFont")
        self.text_font = tkfont.nametofont("TkTextFont")
        self.fixed_font = tkfont.nametofont("TkFixedFont")
        
        # 綁定視窗大小變化事件
        self.root.bind("<Configure>", self.on_window_resize)
        self.root.after(500, self.on_window_resize)  # 初始也執行一次

    def on_window_resize(self, event=None):
        if event and event.widget != self.root:
            return
        width = self.root.winfo_width()
        if width < 800:
            return  # 太小就不調整，避免變得太醜

        # 基準：1200px 寬度時為 1.0 倍
        new_scale = max(0.8, min(width / 1200.0, 2.5))  # 限制 0.8~2.5 倍
        
        if abs(new_scale - self.current_scale) < 0.05:
            return  # 變化太小就不重繪，避免閃爍
        
        self.current_scale = new_scale
        new_size = int(BASE_FONT_SIZE * new_scale)
        new_btn_pad_y = max(4, int(BUTTON_PADDING_Y * new_scale))
        new_btn_pad_x = max(8, int(BUTTON_PADDING_X * new_scale))

        # 更新所有常用字體
        for font_name in ["TkDefaultFont", "TkTextFont", "TkFixedFont", 
                          "Segoe UI", "Noto Sans TC", "clam", "default"]:
            try:
                f = tkfont.nametofont(font_name)
                f.configure(size=new_size)
            except:
                pass

        # 更新 ttk 樣式（按鈕、標籤、輸入框）
        style = ttk.Style()
        style.configure(".", font=("Segoe UI", new_size))
        style.configure("TButton", padding=(new_btn_pad_x, new_btn_pad_y), font=("Segoe UI", new_size))
        style.configure("TLabel", font=("Segoe UI", new_size))
        style.configure("Treeview", font=("Segoe UI", new_size), rowheight=int(26 * new_scale))
        style.configure("Treeview.Heading", font=("Segoe UI", new_size + 1, "bold"))
        style.configure("TCombobox", font=("Segoe UI", new_size))
        style.configure("TCheckbutton", font=("Segoe UI", new_size))
        style.configure("TRadiobutton", font=("Segoe UI", new_size))

        # 特殊處理你的自訂標籤
        style.configure("benign.Treeview", background='#d4edda', foreground='#155724')
        style.configure("malicious.Treeview", background='#f8d7da', foreground='#721c24')

        # 強制更新所有 widget
        self.root.update_idletasks()
# ===============================================================================
def save_config(whitelist_ips, max_threads=4, monitor_mode='local', pcap_file=None,
                cache_timeout=300, pcap_interval=1000, warning_cooldown=60,
                whitelist_ports=None, auto_block=None, flood_enabled=True, flood_high=4500, flood_low=800, flood_ratio=0.02,
                show_benign=False):
    """保存所有設定到 config.json（加強安全性：用臨時檔寫入）"""
    try:
        config = {
            'whitelist_ips': whitelist_ips,
            'max_threads': max_threads,
            'monitor_mode': monitor_mode,
            'pcap_file': pcap_file,
            'cache_timeout': cache_timeout,
            'pcap_interval': pcap_interval,
            'warning_cooldown': warning_cooldown,
            'whitelist_ports': whitelist_ports if whitelist_ports is not None else [],
            'auto_block_ports': auto_block if auto_block is not None else True,
            'flood_protection_enabled': flood_enabled,
            'flood_queue_high': flood_high,
            'flood_queue_low': flood_low,
            'flood_keep_ratio': flood_ratio,
            'show_benign': show_benign
        }
        
        temp_file = CONFIG_FILE + '.tmp'
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
        
        # 寫入成功後才取代原檔
        if os.path.exists(CONFIG_FILE):
            os.replace(temp_file, CONFIG_FILE)  # 原子取代，安全
        else:
            os.rename(temp_file, CONFIG_FILE)
            
        logger.debug(f"配置已成功保存到 {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"保存配置失敗：{str(e)}")
        # 如果失敗，刪除臨時檔
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
def load_config():
    """從 config.json 載入所有設定"""
    default_ports = []
    default_auto_block = True
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                ports = config.get('whitelist_ports', [])
                # 確保是整數列表
                default_ports = [int(p) for p in ports if isinstance(p, (int, str)) and str(p).isdigit()]
                default_auto_block = bool(config.get('auto_block_ports', True))
                global FLOOD_PROTECTION_ENABLED, FLOOD_QUEUE_HIGH, FLOOD_QUEUE_LOW, FLOOD_KEEP_RATIO
                FLOOD_PROTECTION_ENABLED = config.get('flood_protection_enabled', True)
                FLOOD_QUEUE_HIGH = config.get('flood_queue_high', 4500)
                FLOOD_QUEUE_LOW = config.get('flood_queue_low', 800)
                FLOOD_KEEP_RATIO = max(0.001, min(1.0, config.get('flood_keep_ratio', 0.02)))  # 限制 0.1% ~ 100%
                show_benign = bool(config.get('show_benign', False))

                # 同步到全域變數（重要！）
                global whitelist_ports, auto_block_ports
                whitelist_ports = default_ports
                auto_block_ports = default_auto_block
                return (
                    config.get('whitelist_ips', []),
                    config.get('max_threads', 4),
                    config.get('monitor_mode', 'local'),
                    config.get('pcap_file', None),
                    config.get('cache_timeout', 300),
                    config.get('pcap_interval', 1000),
                    config.get('warning_cooldown', 60),
                    default_ports,
                    default_auto_block,
                    show_benign,
                )
    except Exception as e:
        logger.error(f"載入配置失敗，使用預設值：{str(e)}")
def get_local_ip():
    """獲取本機 IP 地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        logger.debug(f"通過 socket 檢測到本機 IP：{local_ip}")
        return local_ip
    except Exception as e:
        logger.warning(f"通過 socket 無法獲取本機 IP：{str(e)}，嘗試使用 psutil")
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        logger.debug(f"通過 psutil 檢測到本機 IP：{addr.address}")
                        return addr.address
            logger.error("通過 psutil 未找到有效本機 IP")
            return None
        except Exception as e:
            logger.error(f"通過 psutil 無法獲取本機 IP：{str(e)}")
            return None
def validate_ip(ip):
    """驗證 IP 地址格式"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
def is_multicast_or_broadcast(ip):
    """檢查 IP 是否為多播或廣播地址"""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr.is_multicast or ip == '255.255.255.255'
    except ValueError:
        return False
def get_training_features():
    """從 selected_features.pkl 載入模型訓練時的確切特徵順序（最準確方式）"""
    features_path = 'C:\\IDS_defense\\models\\selected_features.pkl'
    
    try:
        if os.path.exists(features_path):
            features = joblib.load(features_path)
            if isinstance(features, list) and len(features) > 0:
                logger.info(f"成功從 {features_path} 載入 {len(features)} 個訓練特徵")
                return features
            else:
                raise ValueError("載入的特徵不是有效的列表")
        else:
            raise FileNotFoundError(f"特徵檔案不存在：{features_path}")
    
    except Exception as e:
        logger.error(f"載入訓練特徵失敗：{str(e)}")
        # 後備方案：使用常見的 30 個特徵（避免程式崩潰）
        fallback_features = [
            'ECE Flag Cnt', 'URG Flag Cnt', 'RST Flag Cnt', 'FIN Flag Cnt', 'Bwd URG Flags',
            'ACK Flag Cnt', 'PSH Flag Cnt', 'Bwd PSH Flags', 'SYN Flag Cnt', 'Fwd Header Len',
            'Protocol', 'Dst Port', 'Bwd Header Len', 'Init Bwd Win Byts', 'Src Port',
            'Pkt Size Avg', 'Down/Up Ratio', 'Bwd IAT Max', 'Bwd IAT Mean', 'Bwd Pkts/s',
            'Tot Bwd Pkts', 'Fwd Pkts/s', 'Subflow Bwd Pkts', 'Bwd IAT Tot', 'Flow Duration',
            'Bwd Pkt Len Max', 'Flow IAT Mean', 'Pkt Len Max', 'Flow Pkts/s', 'Bwd Pkt Len Mean'
        ]
        logger.warning("使用內建後備特徵列表（建議檢查 selected_features.pkl 是否存在）")
        return fallback_features
def predict_flow(model, le, flow_df, training_features):
    """預測流量並返回詳細診斷資訊（加強型清理：處理字串、Inf、NaN）"""
    try:
        scaler = joblib.load('C:\\IDS_defense\\models\\scaler.pkl')
        model_feature_names = training_features

        # === 步驟1：強制轉換所有欄位為數值（關鍵修復！）===
        for col in flow_df.columns:
            # 先嘗試轉成 float，失敗的變 NaN
            flow_df[col] = pd.to_numeric(flow_df[col], errors='coerce')

        # === 步驟2：清理異常值 ===
        flow_df = flow_df.replace([np.inf, -np.inf], np.nan)  # Inf → NaN
        flow_df = flow_df.fillna(0)  # NaN → 0

        # === 步驟3：clip 極端值（現在安全了，因為都是 float）===
        flow_df = flow_df.clip(lower=-1e10, upper=1e10)

        # 構建特徵向量
        feature_vector = []
        feature_mapping_info = {}
        for i, model_feat in enumerate(model_feature_names):
            if model_feat in flow_df.columns:
                value = float(flow_df[model_feat].iloc[0])
            else:
                value = 0.0
            feature_vector.append(value)

            if i < 10 or abs(value) > 1e-6:  # 非零值才記錄（避免太多 0）
                feature_mapping_info[model_feat] = {
                    'value': value,
                    'found': model_feat in flow_df.columns
                }

        flow_array = np.array([feature_vector])

        # === 保險：最後檢查 ===
        if np.any(np.isinf(flow_array)) or np.any(np.isnan(flow_array)):
            logger.warning("特徵向量仍有異常值，已強制清理")
            flow_array = np.nan_to_num(flow_array, nan=0.0, posinf=0.0, neginf=0.0)

        # 標準化與預測
        flow_scaled = scaler.transform(flow_array)
        preds = model.predict(flow_scaled)
        preds_proba = model.predict_proba(flow_scaled)[0]
        preds_labels = le.inverse_transform(preds)
        normalized_label = preds_labels[0].lower()

        diagnosis = {
            'label': normalized_label,
            'confidence': float(max(preds_proba)),
            'probabilities': dict(zip(le.classes_, preds_proba)),
            'feature_count': len(feature_vector),
            'sample_features': feature_mapping_info,
            'raw_values': dict(zip(model_feature_names[:10], feature_vector[:10]))
        }
        logger.debug(f"預測成功：{normalized_label}, 置信度：{diagnosis['confidence']:.3f}")
        return normalized_label, diagnosis

    except Exception as e:
        logger.error(f"預測失敗（已安全攔截）：{str(e)}")
        return "benign", {
            'label': 'benign',
            'confidence': 0.0,
            'error': str(e)
        }
def clean_flow_state(flow_state, timeout=120000000):
    """清理超過超時時間的流量狀態"""
    current_time = time.time() * 1e6
    expired_keys = [key for key, state in flow_state.items() if current_time - state['start_time'] > timeout]
    for key in expired_keys:
        del flow_state[key]
    logger.debug(f"已清理流量狀態，剩餘流量數：{len(flow_state)}")
def auto_block_suspicious_port(port, protocol='TCP', features=None):
    """自動封鎖可疑端口，檢查白名單和冷卻"""
    global whitelist_ports
    if port in whitelist_ports:
        logger.info(f"端口 {port} 在白名單中，跳過封鎖")
        return False
    blocked_ports = set() # 可以從防火牆查詢，但簡化為全局 set
    if port in blocked_ports:
        logger.debug(f"端口 {port} 已封鎖，跳過")
        return False
    success = block_port_local(port, protocol)
    if success:
        blocked_ports.add(port)
        logger.info(f"自動封鎖可疑端口 {port} ({protocol})")
        # 更新日志統計
        log_stats['warning'] += 1
        log_stats['top_types'][f"Port Block {port}"] += 1
    return success
def block_port_local(port, protocol='TCP'):
    """在本機使用 netsh 封鎖指定端口"""
    with lock:
        try:
            rule_name = f"IDS_Block_Port_{port}_{protocol}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block localport={port} protocol={protocol}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if result.returncode != 0:
                logger.error(f"無法封鎖端口 {port} ({protocol})：{result.stderr}")
                return False
            logger.info(f"成功封鎖端口 {port} ({protocol})")
            return True
        except Exception as e:
            logger.error(f"封鎖端口 {port} ({protocol}) 時發生錯誤：{str(e)}")
            return False
def unblock_port_local(port, protocol='TCP'):
    """在本機使用 netsh 解除封鎖指定端口"""
    with lock:
        try:
            rule_name = f"IDS_Block_Port_{port}_{protocol}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if result.returncode != 0:
                logger.error(f"無法解除封鎖端口 {port} ({protocol})：{result.stderr}")
                return False
            logger.info(f"成功解除封鎖端口 {port} ({protocol})")
            return True
        except Exception as e:
            logger.error(f"解除封鎖端口 {port} ({protocol}) 時發生錯誤：{str(e)}")
            return False
# 新增：備份 hazard 日誌
def backup_hazard_log():
    """每天自動備份 hazard 日誌"""
    now = datetime.now()
    if now.hour == 0 and now.minute == 0: # 午夜執行
        backup_file = os.path.join(LOG_DIR, f'hazard_backup_{now.strftime("%Y%m%d")}.log')
        if os.path.exists(hazard_log_file):
            subprocess.run(f'copy "{hazard_log_file}" "{backup_file}"', shell=True)
            logger.info(f"已備份 hazard 日誌到 {backup_file}")
class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("本機與遠端入侵檢測系統")
        self.root.geometry("1200x800")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TButton", padding=6, font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("TEntry", font=("Segoe UI", 10))
        self.style.configure("Treeview", font=("Segoe UI", 10))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.packet_table_tags = {
            'Benign': ('benign',),
            'Malicious': ('malicious',)
        }
        self.chart_dirty = {
            'rate': True, 'pie': True, 'proto': True,
            'threat': True, 'ratio': True, 'port': True
        }
        self.style.configure('benign.Treeview', background='#d4edda', foreground='#155724')
        self.style.configure('malicious.Treeview', background='#f8d7da', foreground='#721c24')
        # 載入模型
        self.model_path = available_models[current_model]
        self.model = joblib.load(self.model_path)
        self.le = joblib.load('C:\\IDS_defense\\models\\label_encoder.pkl')
        self.training_features = get_training_features()
        self.flow_state = {}
        self.sniffing = False
        self.sniff_thread = None
        self.sniff_task = None  # 用來取消處理任務
        self.process_thread = None          # 新增：處理佇列執行緒
        self.offline_process = None         # 新增：離線模式 subprocess
        self.stop_event = threading.Event() # 新增：跨執行緒停止旗標
        self.last_detected_ip = None
        self.interface_map = {}
        self.whitelist_ips = []
        self.packet_count = 0
        self.packet_rate = tk.StringVar(value="封包速率：0 packets/s")
        self.start_time = time.time()
        self.detect_start_time = time.time()   # 新增：真正的開始時間（永不重置）
        self.start_time = time.time()          # 保留原來用於速率計算的（但我們改不用了）
        self.local_ip = get_local_ip()
        self.packet_details = {}
        self.monitor_mode = tk.StringVar(value="local")
        self.pcap_file = tk.StringVar(value="")
        self.pcap_dir = 'C:/IDS_defense/pcaps'
        self.csv_dir = 'C:/IDS_defense/csvs'
        self.current_pcap_packets = []
        self.processing_pcap = False
        # === 先載入所有設定（包含 show_benign）===
        (self.whitelist_ips, max_threads, monitor_mode, pcap_file,
         cache_timeout, pcap_interval, warning_cooldown,
         loaded_ports, loaded_auto_block, loaded_show_benign) = load_config()

        self.whitelist_ports = loaded_ports
        self.auto_block_ports = loaded_auto_block

        # === 現在才建立 GUI 變數（確保 loaded_show_benign 已定義）===
        self.show_benign_var = tk.BooleanVar(value=loaded_show_benign)  # 正確！
        self.pcap_interval_ms = tk.StringVar(value="1000")
        self.last_pcap_time = time.time() * 1000
         
        self.whitelist_ports = loaded_ports
        self.auto_block_ports = loaded_auto_block
        self.last_rate_reset = time.time()  # 用於每秒重置 packet_count_sec
        # 同步到 GUI 變數
        self.auto_block_var = tk.BooleanVar(value=self.auto_block_ports)
        self.whitelist_ports_var = tk.StringVar(value=",".join(map(str, self.whitelist_ports)))
        
        # 其他變數照舊
        self.max_threads_var = tk.StringVar(value=str(max_threads))
        self.cache_timeout_var = tk.StringVar(value=str(cache_timeout))
        self.pcap_interval_var = tk.StringVar(value=str(pcap_interval))
        self.warning_cooldown_var = tk.StringVar(value=str(warning_cooldown))
        self.monitor_mode.set(monitor_mode)
        self.pcap_file.set(pcap_file if pcap_file else "")
        self.max_threads_var = tk.StringVar(value=str(max_threads))
        self.cache_timeout_var = tk.StringVar(value=str(cache_timeout))
        self.pcap_interval_var = tk.StringVar(value=str(pcap_interval))
        self.warning_cooldown_var = tk.StringVar(value=str(warning_cooldown))
        self.monitor_mode.set(monitor_mode)
        self.pcap_file.set(pcap_file if pcap_file else "")
        self.executor = ThreadPoolExecutor(max_workers=max_threads)
        self.benign_count = 0
        self.malicious_count = 0
        self.packet_rates = []
        self.timestamps = []
        self.src_ips = Counter()
        self.monitor_window = None
        self.benign_ips = {} # 改為 dict: ip -> timestamp
        self.malicious_ips = {} # 改為 dict: ip -> timestamp
        self.cache_timeout = cache_timeout # 5 分鐘 (秒)
        self.warning_cooldown = warning_cooldown # 警告冷卻時間 (秒)
        self.last_warning = {} # ip -> last_warning_time
        self.search_ip_var = tk.StringVar() # 用於搜索 IP
        self.search_proto_var = tk.StringVar() # 用於篩選協議
        self.detection_data = [] # 用於儲存當前檢測會話的封包數據（包含標籤）
        self.session_timestamp = None # 當前檢測會話的時間戳
        # 新增：端口相關變數
        self.block_port_protocol_var = tk.StringVar(value="TCP")
        self.unblock_port_protocol_var = tk.StringVar(value="TCP")
        self.detect_start_time = None
        # 新增：自動封鎖勾選
        self.auto_block_var = tk.BooleanVar(value=self.auto_block_ports)
        # 新增：模型選擇
        self.model_var = tk.StringVar(value=current_model)
        # 新增：白名單端口
        self.whitelist_ports_var = tk.StringVar(value=",".join(map(str, self.whitelist_ports)))
        # 新增：CPU 使用率顯示
        self.cpu_var = tk.StringVar(value="CPU: 0%")
        # 新增：日志搜索變數
        self.log_search_var = tk.StringVar()
        self.log_level_var = tk.StringVar(value="All")
        self.log_time_start_var = tk.StringVar(value="")
        self.log_time_end_var = tk.StringVar(value="")
        # 新增：流量限速 (每秒最大封包數)
        self.max_packets_per_sec = 1000
        self.packet_count_sec = 0
        self.last_sec_time = time.time()
        # === Flood 保護設定變數 ===
        self.flood_enabled_var = tk.BooleanVar(value=FLOOD_PROTECTION_ENABLED)
        self.flood_high_var = tk.StringVar(value=str(FLOOD_QUEUE_HIGH))
        self.flood_low_var = tk.StringVar(value=str(FLOOD_QUEUE_LOW))
        self.flood_ratio_var = tk.StringVar(value=f"{FLOOD_KEEP_RATIO * 100:.1f}")
        # === 圖形監控專用計數器（必須初始化）===
        self.port_counter = Counter()          # 端口計數（頂部端口條形圖）
        self.protocol_counts = Counter()       # 協議計數（協議餅圖）
        self.ratio_times = []                  # 良惡比率折線圖時間軸
        self.benign_ratios = []                # 良性比例
        self.malicious_ratios = []             # 惡意比例
        self.threat_times = []                 # 威脅事件率時間軸
        self.threat_rates = []                 # 威脅事件率（惡意事件/秒）
        self.full_network_var = tk.BooleanVar(value=False)
        self.last_rate_reset = time.time()  # 初始化速率重置時間
        self.session_pcap_files = []  # 儲存本次檢測產生的 pcap 路徑
        self.session_csv_files = []   # 儲存本次檢測產生的 csv 路徑
        self.session_timestamp = None  # 已經有了，但確保用來當檔名
        self.setup_gui()
        # 啟動 CPU 監控
        self.update_cpu()
        # 啟動日志清理
        self.root.after(10000, self.periodic_cleanup)
            # 保險：如果 10 秒還沒結束，強制恢復按鈕
        def force_resume_button():
            if self.start_button['text'] == "停止中...":
                self.start_button.config(state="normal", text="開始檢測")
                self.log_message("檢測停止超時，強制恢復介面")
        self.root.after(10000, force_resume_button)  # 只在需要時觸發# 只在需要時觸發
    def clear_packet_queue():
        """安全清空 packet_queue（適用於 queue.Queue）"""
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
    def periodic_cleanup(self):
        """定期清理和備份"""
        clean_flow_state(self.flow_state)
        backup_hazard_log()
        self.root.after(10000, self.periodic_cleanup)
    def update_cpu(self):
        cpu = psutil.cpu_percent(interval=1)
        self.cpu_var.set(f"CPU: {cpu:.1f}%")
        if cpu > 80:
            logger.warning("CPU 過高，自動降頻圖表更新")
            # 強制把所有動畫間隔變長
            for ani_name in ['rate_ani', 'pie_ani', 'proto_ani', 'threat_ani', 'ratio_ani', 'port_ani']:
                if hasattr(self, ani_name):
                    ani = getattr(self, ani_name)
                    if ani: ani._interval = 10000  # 變 10 秒更新一次
        self.root.after(5000, self.update_cpu)
    def load_model(self):
        """載入新模型"""
        model_name = self.model_var.get()
        model_path = available_models.get(model_name)
        if not model_path or not os.path.exists(model_path):
            messagebox.showerror("錯誤", f"模型檔案不存在：{model_path}")
            return
        try:
            self.model = joblib.load(model_path)
            global current_model
            current_model = model_name
            # 簡單驗證：假設有測試數據，計算準確率
            # test_acc = self.model.score(test_X, test_y) # 需要載入測試數據
            self.log_message(f"已載入模型：{model_name}")
            messagebox.showinfo("成功", f"模型 {model_name} 已載入")
        except Exception as e:
            self.log_message(f"載入模型失敗：{str(e)}")
            messagebox.showerror("錯誤", str(e))
    def setup_gui(self):
        """設置主 GUI 元素，使用 Notebook 分頁"""
        main_frame = ttk.Frame(self.root, padding=10, style="Main.TFrame")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        # 創建 Notebook (標籤頁)
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=0, column=0, sticky="nsew", pady=5)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        # 第一頁: 控制面板
        control_tab = ttk.Frame(notebook, padding=10)
        notebook.add(control_tab, text="控制面板")
        self.setup_control_tab(control_tab)
        # 第二頁: 封包監控
        packets_tab = ttk.Frame(notebook, padding=10)
        notebook.add(packets_tab, text="封包監控")
        self.setup_packets_tab(packets_tab)
        # 第三頁: 檢測日誌
        log_tab = ttk.Frame(notebook, padding=10)
        notebook.add(log_tab, text="檢測日誌")
        self.setup_log_tab(log_tab)
        # 第四頁: 設定
        settings_tab = ttk.Frame(notebook, padding=10)
        notebook.add(settings_tab, text="設定")
        self.setup_settings_tab(settings_tab)
        self.update_interfaces()
        self.update_packet_rate()
        self.tooltip_window = None
        self.toggle_monitor_mode()
    def setup_settings_tab(self, parent):
        """設置頁面"""
        settings_frame = ttk.LabelFrame(parent, text="設定", padding=10)
        settings_frame.grid(row=0, column=0, sticky="nsew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        settings_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(settings_frame, text="最大執行緒數:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(settings_frame, textvariable=self.max_threads_var).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(settings_frame, text="快取檢測時間 (秒):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(settings_frame, textvariable=self.cache_timeout_var).grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(settings_frame, text="流量檢測間隔 (毫秒):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(settings_frame, textvariable=self.pcap_interval_var).grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(settings_frame, text="警告冷卻時間 (秒):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(settings_frame, textvariable=self.warning_cooldown_var).grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        ttk.Checkbutton(settings_frame, text="顯示所有良性（Benign）封包到表格（可能影響效能）",
                        variable=self.show_benign_var).grid(row=9, column=0, columnspan=2, padx=5, pady=8, sticky="w")
        # 新增：模型選擇
        ttk.Label(settings_frame, text="模型選擇:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.model_combo = ttk.Combobox(settings_frame, textvariable=self.model_var, values=list(available_models.keys()), state="readonly")
        self.model_combo.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(settings_frame, text="載入模型", command=self.load_model).grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        # 新增：白名單端口
        ttk.Label(settings_frame, text="白名單端口 (逗號分隔):").grid(row=6, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(settings_frame, textvariable=self.whitelist_ports_var).grid(row=6, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(settings_frame, text="保存白名單端口", command=self.save_whitelist_ports).grid(row=7, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        # 新增：自動封鎖勾選
        ttk.Checkbutton(settings_frame, text="啟用自動封鎖可疑端口", 
                       variable=self.auto_block_var).grid(row=8, column=0, columnspan=2, padx=5, pady=8, sticky="w")
        # === Flood 保護設定區塊 ===
        flood_frame = ttk.LabelFrame(settings_frame, text="Flood / DoS 保護設定", padding=10)
        flood_frame.grid(row=10, column=0, columnspan=2, padx=5, pady=10, sticky="ew")

        ttk.Checkbutton(flood_frame, text="啟用 Flood 保護機制",
                        variable=self.flood_enabled_var).grid(row=0, column=0, columnspan=2, sticky="w", pady=2)

        ttk.Label(flood_frame, text="佇列上限（觸發丟包）:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(flood_frame, textvariable=self.flood_high_var, width=10).grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(flood_frame, text="佇列下限（恢復正常）:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(flood_frame, textvariable=self.flood_low_var, width=10).grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(flood_frame, text="Flood 時保留比例（%）:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(flood_frame, textvariable=self.flood_ratio_var, width=10).grid(row=3, column=1, sticky="w", pady=2)
        ttk.Label(flood_frame, text="（範圍 0.1 ~ 100，建議 1~5）", foreground="gray").grid(row=4, column=0, columnspan=2, sticky="w", padx=5)   
        
        
        # === 儲存設定按鈕與狀態顯示 ===
        save_button_frame = ttk.Frame(settings_frame)
        save_button_frame.grid(row=11, column=0, columnspan=2, pady=20)

        ttk.Button(save_button_frame, text="儲存所有設定", command=self.save_settings).grid(row=0, column=0, padx=10)

        # 狀態標籤（預設隱藏）
        self.settings_status_label = ttk.Label(save_button_frame, text="", foreground="green", font=("Segoe UI", 10, "bold"))
        self.settings_status_label.grid(row=0, column=1)

        # 提示文字
        ttk.Label(settings_frame, text="※ 修改設定後請點擊「儲存所有設定」按鈕，程式重啟後生效", 
                  foreground="gray").grid(row=12, column=0, columnspan=2, pady=5) 
    def save_whitelist_ports(self):
        """保存白名單端口"""
        ports_input = self.whitelist_ports_var.get().strip()
        ports = []
        if ports_input:
            for p in ports_input.split(","):
                p = p.strip()
                if p.isdigit() and 1 <= int(p) <= 65535:
                    ports.append(int(p))
                elif p:  # 有輸入但不是數字
                    messagebox.showwarning("警告", f"無效端口被忽略：{p}")
        
        self.whitelist_ports = ports
        global whitelist_ports
        whitelist_ports = ports
        
        # 直接保存（包含自動封鎖狀態）
        save_config(
            self.whitelist_ips,
            int(self.max_threads_var.get() or 4),
            self.monitor_mode.get(),
            self.pcap_file.get() or None,
            int(self.cache_timeout_var.get() or 300),
            int(self.pcap_interval_var.get() or 1000),
            int(self.warning_cooldown_var.get() or 60),
            self.whitelist_ports,
            self.auto_block_var.get()
        )
        
        self.log_message(f"白名單端口已保存：{ports}")
        messagebox.showinfo("成功", f"白名單端口已保存（{len(ports)} 個）")
    def save_settings(self):
        """保存所有設定（包含自動封鎖、Flood 保護等）並顯示確認訊息"""
        try:
            # === 安全讀取所有輸入值（防止空字串或無效值導致崩潰）===
            try:
                max_threads = int(self.max_threads_var.get() or "4")
                cache_timeout = int(self.cache_timeout_var.get() or "300")
                pcap_interval = int(self.pcap_interval_var.get() or "1000")
                warning_cooldown = int(self.warning_cooldown_var.get() or "60")
            except ValueError as ve:
                messagebox.showerror("錯誤", f"請確認數字欄位填寫正確：{ve}")
                return

            # === Flood 保護參數驗證 ===
            flood_enabled = self.flood_enabled_var.get()
            try:
                flood_high_str = self.flood_high_var.get().strip()
                flood_low_str = self.flood_low_var.get().strip()
                flood_ratio_str = self.flood_ratio_var.get().strip()

                flood_high = int(flood_high_str) if flood_high_str else 4500
                flood_low = int(flood_low_str) if flood_low_str else 800
                flood_ratio_percent = float(flood_ratio_str.replace('%', '')) if flood_ratio_str else 2.0
                flood_ratio = flood_ratio_percent / 100.0

                if not (100 <= flood_high <= 6000):
                    raise ValueError("佇列上限必須在 100~6000 之間")
                if not (50 <= flood_low < flood_high):
                    raise ValueError("佇列下限必須小於上限，且至少 50")
                if not (0.1 <= flood_ratio_percent <= 100):
                    raise ValueError("保留比例必須在 0.1% ~ 100% 之間")
            except ValueError as ve:
                messagebox.showerror("錯誤", f"Flood 保護參數錯誤：{ve}")
                return

            # === 基本驗證 ===
            if not (1 <= max_threads <= 16):
                raise ValueError("執行緒數必須在 1~16 之間")
            if cache_timeout <= 0 or pcap_interval <= 0 or warning_cooldown <= 0:
                raise ValueError("時間設定必須大於 0")

            # === 安全更新執行緒池（關鍵！不中斷背景任務）===
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except:
                pass  # 忽略任何錯誤

            self.executor = ThreadPoolExecutor(max_workers=max_threads)
            self.log_message(f"執行緒數已安全更新為 {max_threads}（背景任務不受影響）")

            # 更新其他變數
            self.cache_timeout = cache_timeout
            self.warning_cooldown = warning_cooldown

            # 同步全域變數
            global auto_block_ports, whitelist_ports
            global FLOOD_PROTECTION_ENABLED, FLOOD_QUEUE_HIGH, FLOOD_QUEUE_LOW, FLOOD_KEEP_RATIO
            auto_block_ports = self.auto_block_var.get()
            whitelist_ports = self.whitelist_ports

            FLOOD_PROTECTION_ENABLED = flood_enabled
            FLOOD_QUEUE_HIGH = flood_high
            FLOOD_QUEUE_LOW = flood_low
            FLOOD_KEEP_RATIO = flood_ratio

            # === 安全儲存設定 ===
            save_config(
                self.whitelist_ips,
                max_threads,
                self.monitor_mode.get(),
                self.pcap_file.get() or None,
                cache_timeout,
                pcap_interval,
                warning_cooldown,
                self.whitelist_ports,
                auto_block_ports,
                FLOOD_PROTECTION_ENABLED,
                FLOOD_QUEUE_HIGH,
                FLOOD_QUEUE_LOW,
                FLOOD_KEEP_RATIO,
                self.show_benign_var.get()
            )

            # === 成功訊息 ===
            self.settings_status_label.config(text="已成功保存所有設定！", foreground="green")
            self.root.update_idletasks()
            self.root.after(3000, lambda: self.settings_status_label.config(text=""))
            self.log_message("所有設定已成功保存")

        except Exception as e:
            # 任何未預期的錯誤都捕捉，避免程式崩潰
            error_msg = f"儲存設定時發生未知錯誤：{str(e)}"
            logger.error(error_msg)
            self.settings_status_label.config(text="保存失敗", foreground="red")
            self.root.after(3000, lambda: self.settings_status_label.config(text=""))
            messagebox.showerror("錯誤", error_msg)
    def setup_control_tab(self, parent):
        """設置控制面板頁"""
        control_frame = ttk.LabelFrame(parent, text="控制面板", padding=10)
        control_frame.grid(row=0, column=0, sticky="nsew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        control_frame.grid_columnconfigure(1, weight=1)
        ttk.Button(control_frame, text="開啟圖形監控", command=self.toggle_monitor_window).grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        ttk.Label(control_frame, text=f"本機 IP: {self.local_ip if self.local_ip else '無法獲取'}").grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        # 新增 CPU 顯示
        ttk.Label(control_frame, textvariable=self.cpu_var).grid(row=1, column=2, padx=5, pady=5, sticky="e")
        monitor_frame = ttk.LabelFrame(control_frame, text="監控模式", padding=5)
        monitor_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=5)
        ttk.Checkbutton(monitor_frame, text="全網監控模式（看到路由器等設備被攻擊）",
                variable=self.full_network_var).grid(row=1, column=0, columnspan=3, pady=5)
        ttk.Radiobutton(monitor_frame, text="本機監控", value="local", variable=self.monitor_mode, command=self.toggle_monitor_mode).grid(row=0, column=0, padx=5, pady=5)
        ttk.Radiobutton(monitor_frame, text="離線模式 (.pcap)", value="offline", variable=self.monitor_mode, command=self.toggle_monitor_mode).grid(row=0, column=2, padx=5, pady=5)
        self.pcap_label = ttk.Label(monitor_frame, text="pcap 檔案:")
        self.pcap_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.pcap_entry = ttk.Entry(monitor_frame, textvariable=self.pcap_file, state="readonly")
        self.pcap_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.pcap_button = ttk.Button(monitor_frame, text="選擇 .pcap 檔案", command=self.select_pcap_file)
        self.pcap_button.grid(row=2, column=2, padx=5, pady=5)
        self.interface_label = ttk.Label(control_frame, text="網路介面:")
        self.interface_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly")
        self.interface_combo.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.interface_combo.bind("<Enter>", lambda e: self.show_tooltip(self.interface_combo, "選擇要監控的網路介面"))
        self.interface_combo.bind("<Leave>", self.hide_tooltip)
        ttk.Label(control_frame, text="白名單 IP（逗號分隔）:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.whitelist_var = tk.StringVar(value=",".join(self.whitelist_ips))
        ttk.Entry(control_frame, textvariable=self.whitelist_var).grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(control_frame, text="保存白名單", command=self.save_whitelist).grid(row=4, column=2, padx=5, pady=5)
        control_frame.children['!entry'].bind("<Enter>", lambda e: self.show_tooltip(control_frame.children['!entry'], "輸入以逗號分隔的 IP 地址"))
        control_frame.children['!entry'].bind("<Leave>", self.hide_tooltip)
        ttk.Button(control_frame, text="查看歷史異常報告", command=self.view_hazard_logs).grid(row=8, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        # 新增查看已封鎖端口列表按鈕
        ttk.Button(control_frame, text="查看已封鎖端口列表", command=self.view_blocked_ports).grid(row=10, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        ttk.Label(control_frame, text="要封鎖的端口:").grid(row=11, column=0, padx=5, pady=5, sticky="w")
        self.block_port_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.block_port_var).grid(row=11, column=1, padx=5, pady=5, sticky="ew")
        # 新增協議選擇
        protocol_frame = ttk.Frame(control_frame)
        protocol_frame.grid(row=11, column=2, padx=5, pady=5, sticky="w")
        ttk.Label(protocol_frame, text="協議:").grid(row=0, column=0, padx=2, pady=2)
        self.block_port_protocol_combo = ttk.Combobox(protocol_frame, textvariable=self.block_port_protocol_var, values=['TCP', 'UDP', 'Both'], state="readonly", width=8)
        self.block_port_protocol_combo.grid(row=0, column=1, padx=2, pady=2)
        ttk.Button(protocol_frame, text="封鎖端口", command=self.manual_block_port).grid(row=0, column=2, padx=2, pady=2)
        ttk.Label(control_frame, text="要解除封鎖的端口:").grid(row=12, column=0, padx=5, pady=5, sticky="w")
        self.unblock_port_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.unblock_port_var).grid(row=12, column=1, padx=5, pady=5, sticky="ew")
        # 新增解除協議選擇
        unblock_protocol_frame = ttk.Frame(control_frame)
        unblock_protocol_frame.grid(row=12, column=2, padx=5, pady=5, sticky="w")
        ttk.Label(unblock_protocol_frame, text="協議:").grid(row=0, column=0, padx=2, pady=2)
        self.unblock_port_protocol_combo = ttk.Combobox(unblock_protocol_frame, textvariable=self.unblock_port_protocol_var, values=['TCP', 'UDP', 'Both'], state="readonly", width=8)
        self.unblock_port_protocol_combo.grid(row=0, column=1, padx=2, pady=2)
        ttk.Button(unblock_protocol_frame, text="解除封鎖端口", command=self.unblock_port).grid(row=0, column=2, padx=2, pady=2)
    def setup_packets_tab(self, parent):
        """設置封包監控頁"""
        table_container = ttk.Frame(parent)
        table_container.grid(row=0, column=0, sticky="nsew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)
        table_container.grid_columnconfigure(1, weight=1)
        table_container.grid_rowconfigure(0, weight=1)
        benign_table_frame = ttk.LabelFrame(table_container, text="正常封包", padding=10)
        benign_table_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        benign_table_frame.grid_columnconfigure(0, weight=1)
        benign_table_frame.grid_rowconfigure(0, weight=1)
        self.benign_table = ttk.Treeview(
            benign_table_frame,
            columns=("Time", "Source IP", "Destination IP", "Protocol", "Label"),
            show="headings",
            style="benign.Treeview"
        )
        self.benign_table.heading("Time", text="時間")
        self.benign_table.heading("Source IP", text="來源 IP")
        self.benign_table.heading("Destination IP", text="目的 IP")
        self.benign_table.heading("Protocol", text="協議")
        self.benign_table.heading("Label", text="標籤")
        self.benign_table.column("Time", width=150)
        self.benign_table.column("Source IP", width=100)
        self.benign_table.column("Destination IP", width=100)
        self.benign_table.column("Protocol", width=80)
        self.benign_table.column("Label", width=100)
        self.benign_table.grid(row=0, column=0, sticky="nsew")
        self.benign_table.bind("<Double-1>", self.show_packet_details)
        benign_scroll_y = ttk.Scrollbar(benign_table_frame, orient="vertical", command=self.benign_table.yview)
        benign_scroll_y.grid(row=0, column=1, sticky="ns")
        benign_scroll_x = ttk.Scrollbar(benign_table_frame, orient="horizontal", command=self.benign_table.xview)
        benign_scroll_x.grid(row=1, column=0, sticky="ew")
        self.benign_table.configure(yscrollcommand=benign_scroll_y.set, xscrollcommand=benign_scroll_x.set)
        malicious_table_frame = ttk.LabelFrame(table_container, text="異常封包", padding=10)
        malicious_table_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        malicious_table_frame.grid_columnconfigure(0, weight=1)
        malicious_table_frame.grid_rowconfigure(0, weight=1)
        self.malicious_table = ttk.Treeview(
            malicious_table_frame,
            columns=("Time", "Source IP", "Destination IP", "Protocol", "Label"),
            show="headings",
            style="malicious.Treeview"
        )
        self.malicious_table.heading("Time", text="時間")
        self.malicious_table.heading("Source IP", text="來源 IP")
        self.malicious_table.heading("Destination IP", text="目的 IP")
        self.malicious_table.heading("Protocol", text="協議")
        self.malicious_table.heading("Label", text="標籤")
        self.malicious_table.column("Time", width=150)
        self.malicious_table.column("Source IP", width=100)
        self.malicious_table.column("Destination IP", width=100)
        self.malicious_table.column("Protocol", width=80)
        self.malicious_table.column("Label", width=100)
        self.malicious_table.grid(row=0, column=0, sticky="nsew")
        self.malicious_table.bind("<Double-1>", self.show_packet_details)
        malicious_scroll_y = ttk.Scrollbar(malicious_table_frame, orient="vertical", command=self.malicious_table.yview)
        malicious_scroll_y.grid(row=0, column=1, sticky="ns")
        malicious_scroll_x = ttk.Scrollbar(malicious_table_frame, orient="horizontal", command=self.malicious_table.xview)
        malicious_scroll_x.grid(row=1, column=0, sticky="ew")
        self.malicious_table.configure(yscrollcommand=malicious_scroll_y.set, xscrollcommand=malicious_scroll_x.set)
        # 添加篩選功能
        filter_frame = ttk.Frame(parent)
        filter_frame.grid(row=2, column=0, sticky="ew", pady=5)
        ttk.Label(filter_frame, text="篩選 IP:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Entry(filter_frame, textvariable=self.search_ip_var).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(filter_frame, text="篩選協議:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.protocol_combo = ttk.Combobox(filter_frame, textvariable=self.search_proto_var, state="readonly")
        self.protocol_combo['values'] = ['All', 'TCP', 'UDP', 'ICMP', 'IGMP', 'IPv6', 'IPv6 Hop-by-Hop', 'IP over IP']
        self.protocol_combo.set('All')
        self.protocol_combo.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        ttk.Button(filter_frame, text="套用篩選", command=self.apply_filter).grid(row=0, column=4, padx=5, pady=5)
        ttk.Button(filter_frame, text="清除篩選", command=self.clear_filter).grid(row=0, column=5, padx=5, pady=5)
        filter_frame.grid_columnconfigure(1, weight=1)
        filter_frame.grid_columnconfigure(3, weight=1)
        # 封包速率和開始按鈕放在底部
        bottom_frame = ttk.Frame(parent)
        bottom_frame.grid(row=3, column=0, sticky="ew", pady=5)
        ttk.Label(bottom_frame, textvariable=self.packet_rate).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.start_button = ttk.Button(bottom_frame, text="開始檢測", command=self.toggle_sniffing)
        self.start_button.grid(row=0, column=1, padx=5, pady=5, sticky="e")
        ttk.Button(bottom_frame, text="清理封包表格", command=self.clear_packet_tables).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(bottom_frame, text="匯出檢測表格", command=self.export_detection_table).grid(row=0, column=3, padx=5, pady=5)
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=0)
    def apply_filter(self):
        """套用 IP 和協議篩選"""
        search_ip = self.search_ip_var.get().strip().lower()
        search_proto = self.search_proto_var.get()
        if search_proto == 'All':
            search_proto = ''
        for table in [self.benign_table, self.malicious_table]:
            for item in table.get_children():
                values = table.item(item, "values")
                src_ip = values[1].lower()
                dst_ip = values[2].lower()
                proto = values[3]
                if (search_ip and search_ip not in src_ip and search_ip not in dst_ip) or (search_proto and search_proto != proto):
                    table.detach(item)
        self.log_message(f"已套用篩選：IP={search_ip or '無'}, 協議={search_proto or '無'}")
    def clear_filter(self):
        """清除篩選"""
        for table in [self.benign_table, self.malicious_table]:
            for item in table.get_children(''):
                table.reattach(item, '', 'end')
        self.search_ip_var.set('')
        self.search_proto_var.set('All')
        self.log_message("已清除篩選")
    def setup_log_tab(self, parent):
        """設置檢測日誌頁，使用 Treeview 表格化顯示"""
        log_frame = ttk.LabelFrame(parent, text="檢測日誌", padding=10)
        log_frame.grid(row=0, column=0, sticky="nsew")
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)
        # 新增：搜索框架
        search_frame = ttk.Frame(log_frame)
        search_frame.grid(row=0, column=0, sticky="ew", pady=5)
        ttk.Label(search_frame, text="搜索關鍵字:").grid(row=0, column=0, padx=5)
        ttk.Entry(search_frame, textvariable=self.log_search_var).grid(row=0, column=1, padx=5, sticky="ew")
        ttk.Label(search_frame, text="層級:").grid(row=0, column=2, padx=5)
        self.log_level_combo = ttk.Combobox(search_frame, textvariable=self.log_level_var, values=['All', 'INFO', 'WARNING', 'ERROR'], state="readonly")
        self.log_level_combo.grid(row=0, column=3, padx=5, sticky="ew")
        ttk.Label(search_frame, text="時間起:").grid(row=0, column=4, padx=5)
        ttk.Entry(search_frame, textvariable=self.log_time_start_var, width=10).grid(row=0, column=5, padx=5)
        ttk.Label(search_frame, text="時間止:").grid(row=0, column=6, padx=5)
        ttk.Entry(search_frame, textvariable=self.log_time_end_var, width=10).grid(row=0, column=7, padx=5)
        ttk.Button(search_frame, text="搜索", command=self.search_logs).grid(row=0, column=8, padx=5)
        ttk.Button(search_frame, text="清除", command=self.clear_log_search).grid(row=0, column=9, padx=5)
        ttk.Button(search_frame, text="匯出日志", command=self.export_log).grid(row=0, column=10, padx=5)
        search_frame.grid_columnconfigure(1, weight=1)
        search_frame.grid_columnconfigure(3, weight=1)
        # 日志表格
        self.log_tree = ttk.Treeview(
            log_frame,
            columns=("Time", "Level", "Message"),
            show="headings"
        )
        self.log_tree.heading("Time", text="時間")
        self.log_tree.heading("Level", text="層級")
        self.log_tree.heading("Message", text="訊息")
        self.log_tree.column("Time", width=200)
        self.log_tree.column("Level", width=100)
        self.log_tree.column("Message", width=800)
        self.log_tree.grid(row=1, column=0, sticky="nsew")
        log_scroll_y = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_tree.yview)
        log_scroll_y.grid(row=1, column=1, sticky="ns")
        self.log_tree.configure(yscrollcommand=log_scroll_y.set)
        # 新增：日志統計
        self.stats_label = ttk.Label(log_frame, text="日志統計：總計 0 | 警告 0 | 頂部類型: 無")
        self.stats_label.grid(row=2, column=0, sticky="w", pady=5)
        self.gui_handler = TreeviewHandler(self.log_tree)
        self.gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(self.gui_handler)
    
    def search_logs(self):
        """搜索日志"""
        keyword = self.log_search_var.get().lower()
        level = self.log_level_var.get()
        start_time = self.log_time_start_var.get()
        end_time = self.log_time_end_var.get()
        for item in self.log_tree.get_children():
            values = self.log_tree.item(item, "values")
            time_str, level_str, msg = values
            match = True
            if keyword and keyword not in msg.lower():
                match = False
            if level != 'All' and level != level_str:
                match = False
            if start_time and start_time > time_str:
                match = False
            if end_time and end_time < time_str:
                match = False
            if not match:
                self.log_tree.detach(item)
        self.log_message("日志搜索已套用")
    def clear_log_search(self):
        """清除日志搜索"""
        for item in self.log_tree.get_children(''):
            self.log_tree.reattach(item, '', 'end')
        self.log_search_var.set('')
        self.log_level_var.set('All')
        self.log_time_start_var.set('')
        self.log_time_end_var.set('')
        self.log_message("日志搜索已清除")
    def export_log(self):
        """匯出日志到 CSV"""
        if not self.log_tree.get_children():
            messagebox.showerror("錯誤", "無日志可匯出")
            return
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_path = os.path.join(LOG_DIR, f"log_export_{timestamp}.csv")
            data = [self.log_tree.item(item, "values") for item in self.log_tree.get_children()]
            df = pd.DataFrame(data, columns=["Time", "Level", "Message"])
            df.to_csv(export_path, index=False, encoding='utf-8-sig')
            self.log_message(f"日志已匯出到 {export_path}")
            messagebox.showinfo("成功", f"日志已匯出到 {export_path}")
        except Exception as e:
            self.log_message(f"匯出日志失敗：{str(e)}")
            messagebox.showerror("錯誤", str(e))
    def update_log_stats(self):
        """更新日志統計"""
        total = len(self.log_tree.get_children())
        warnings = len([item for item in self.log_tree.get_children() if self.log_tree.item(item, "values")[1] == "WARNING"])
        top_type = log_stats['top_types'].most_common(1)[0][0] if log_stats['top_types'] else "無"
        self.stats_label.config(text=f"日志統計：總計 {total} | 警告 {warnings} | 頂部類型: {top_type}")
    # 其他方法保持原樣，僅在相關處呼叫新功能
    def apply_pcap_interval(self):
        """驗證並應用 PCAP 生成時間間隔"""
        try:
            interval = int(self.pcap_interval_ms.get())
            if interval <= 0:
                raise ValueError("間隔必須大於 0")
            logger.info(f"已設置 PCAP 生成間隔為 {interval} 毫秒")
            self.log_message(f"已設置 PCAP 生成間隔為 {interval} 毫秒")
        except ValueError as e:
            logger.error(f"無效的時間間隔：{str(e)}")
            self.log_message(f"無效的時間間隔：{str(e)}")
            self.root.after(0, lambda: messagebox.showerror("錯誤", f"請輸入有效的正整數間隔（毫秒）"))
    def toggle_monitor_window(self):
        """開啟或關閉圖形監控視窗"""
        if self.monitor_window is None or not self.monitor_window.winfo_exists():
            self.monitor_window = tk.Toplevel(self.root)
            self.monitor_window.title("圖形監控面板")
            self.monitor_window.geometry("1200x400")
            self.setup_graphical_monitor(self.monitor_window)
            self.monitor_window.protocol("WM_DELETE_WINDOW", self.close_monitor_window)
            self.log_message("已開啟圖形監控視窗")
        else:
            self.close_monitor_window()
    def close_monitor_window(self):
        """關閉圖形監控視窗 - 安全釋放所有動畫"""
        if self.monitor_window:
            # 停止所有動畫
            for ani in ['rate_ani', 'pie_ani', 'proto_ani', 'threat_ani', 'ratio_ani', 'port_ani']:
                if hasattr(self, ani):
                    getattr(self, ani)._stop()  # 強制停止
                    setattr(self, ani, None)
            self.monitor_window.destroy()
            self.monitor_window = None
            self.log_message("已關閉圖形監控視窗")
    def setup_graphical_monitor(self, parent):
        """設置圖形監控面板 - 6張專業圖表完整版（終極穩定版）"""
        monitor_frame = ttk.LabelFrame(parent, text="圖形監控面板", padding=10)
        monitor_frame.grid(row=0, column=0, sticky="nsew")
        monitor_frame.grid_rowconfigure(0, weight=1)
        monitor_frame.grid_rowconfigure(1, weight=1)
        monitor_frame.grid_columnconfigure(0, weight=1)
        monitor_frame.grid_columnconfigure(1, weight=1)
        monitor_frame.grid_columnconfigure(2, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # 第一排
        self.rate_fig, self.rate_ax = plt.subplots(figsize=(5, 3))
        self.rate_line, = self.rate_ax.plot([], [], 'b-', linewidth=2)
        self.rate_ax.set_title("即時封包速率")
        self.rate_ax.set_xlabel("時間 (秒)")
        self.rate_ax.set_ylabel("速率 (packets/s)")
        self.rate_canvas = FigureCanvasTkAgg(self.rate_fig, master=monitor_frame)
        self.rate_canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.pie_fig, self.pie_ax = plt.subplots(figsize=(5, 3))
        self.pie_ax.set_title("正常 vs 惡意封包")
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=monitor_frame)
        self.pie_canvas.get_tk_widget().grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        self.proto_fig, self.proto_ax = plt.subplots(figsize=(5, 3))
        self.proto_ax.set_title("協議分佈")
        self.proto_canvas = FigureCanvasTkAgg(self.proto_fig, master=monitor_frame)
        self.proto_canvas.get_tk_widget().grid(row=0, column=2, sticky="nsew", padx=5, pady=5)

        # 第二排
        self.threat_fig, self.threat_ax = plt.subplots(figsize=(5, 3))
        self.threat_line, = self.threat_ax.plot([], [], 'r-', linewidth=2)
        self.threat_ax.set_title("威脅事件率 (events/s)")
        self.threat_ax.set_ylabel("惡意事件/秒")
        self.threat_canvas = FigureCanvasTkAgg(self.threat_fig, master=monitor_frame)
        self.threat_canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        self.ratio_fig, self.ratio_ax = plt.subplots(figsize=(5, 3))
        self.b_line, = self.ratio_ax.plot([], [], 'g-', label='正常', linewidth=2)
        self.m_line, = self.ratio_ax.plot([], [], 'r-', label='惡意', linewidth=2)
        self.ratio_ax.legend()
        self.ratio_ax.set_title("良惡流量比例 (%)")
        self.ratio_ax.set_ylim(0, 100)
        self.ratio_canvas = FigureCanvasTkAgg(self.ratio_fig, master=monitor_frame)
        self.ratio_canvas.get_tk_widget().grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        self.port_fig, self.port_ax = plt.subplots(figsize=(5, 3))
        self.port_ax.set_title("熱門端口 Top 5")
        self.port_ax.set_xlabel("端口號")
        self.port_ax.set_ylabel("封包數")
        self.port_canvas = FigureCanvasTkAgg(self.port_fig, master=monitor_frame)
        self.port_canvas.get_tk_widget().grid(row=1, column=2, sticky="nsew", padx=5, pady=5)

        # 啟動動畫（關鍵：去掉 blit=False + 合理間隔）
        self.rate_ani   = FuncAnimation(self.rate_fig,   self.update_rate_chart,   interval=1000, cache_frame_data=False)
        self.pie_ani    = FuncAnimation(self.pie_fig,    self.update_pie_chart,    interval=2000, cache_frame_data=False)
        self.proto_ani  = FuncAnimation(self.proto_fig,  self.update_protocol_pie, interval=5000, cache_frame_data=False)
        self.threat_ani = FuncAnimation(self.threat_fig, self.update_threat_line,  interval=1500, cache_frame_data=False)
        self.ratio_ani  = FuncAnimation(self.ratio_fig,  self.update_ratio_line,   interval=1500, cache_frame_data=False)
        self.port_ani   = FuncAnimation(self.port_fig,   self.update_port_bar,     interval=8000, cache_frame_data=False)
    def update_protocol_pie(self, frame):
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        if sum(self.protocol_counts.values()) == 0:
            return
        labels = list(self.protocol_counts.keys())
        sizes = list(self.protocol_counts.values())
        self.proto_ax.clear()
        self.proto_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        self.proto_ax.set_title("協議分佈")
        self.proto_canvas.draw()
    def update_threat_line(self, frame):
        """威脅事件率 - 紅色線條平滑顯示"""
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        if self.detect_start_time is None:
            return

        current_time = time.time() - self.detect_start_time
        elapsed = max(current_time, 1)
        current_threat_rate = self.malicious_count / elapsed

        # 每秒更新一次
        if not self.threat_times or abs(self.threat_times[-1] - current_time) >= 0.9:
            self.threat_times.append(current_time)
            self.threat_rates.append(current_threat_rate)

            if len(self.threat_times) > 300:
                self.threat_times.pop(0)
                self.threat_rates.pop(0)

        self.threat_ax.clear()
        self.threat_ax.plot(self.threat_times, self.threat_rates, 'r-', linewidth=2.5)
        self.threat_ax.fill_between(self.threat_times, self.threat_rates, alpha=0.3, color='red')
        self.threat_ax.set_title("威脅事件率 (events/s)", fontsize=12, fontweight='bold')
        self.threat_ax.set_xlabel("時間 (秒)")
        self.threat_ax.set_ylabel("惡意事件/秒")
        self.threat_ax.grid(True, alpha=0.3)
        self.threat_ax.set_ylim(bottom=0)

        if self.threat_rates:
            max_threat = max(self.threat_rates)
            self.threat_ax.set_ylim(0, max(max_threat * 1.5, 0.1))

        self.threat_canvas.draw()

    def update_ratio_line(self, frame):
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        
        total = self.benign_count + self.malicious_count
        if total == 0:
            return

        t = len(self.ratio_times)
        self.ratio_times.append(t)
        b_ratio = self.benign_count / total * 100
        m_ratio = self.malicious_count / total * 100
        self.benign_ratios.append(b_ratio)
        self.malicious_ratios.append(m_ratio)

        if len(self.ratio_times) > 60:
            self.ratio_times.pop(0)
            self.benign_ratios.pop(0)
            self.malicious_ratios.pop(0)

        self.ratio_ax.clear()
        self.ratio_ax.plot(self.ratio_times, self.benign_ratios, 'g-', label='正常', linewidth=2)
        self.ratio_ax.plot(self.ratio_times, self.malicious_ratios, 'r-', label='惡意', linewidth=2)
        self.ratio_ax.legend()
        self.ratio_ax.set_ylim(0, 100)
        self.ratio_ax.set_title("惡意事件累積數（總攻擊量）")
        self.ratio_ax.grid(True, alpha=0.3)
        self.ratio_canvas.draw()
    def update_ratio_line(self, frame):  # 改名也沒關係，或直接取代原位置
        """惡意事件累積數 """
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return

        current_time = time.time() - self.detect_start_time
        current_cumulative = self.malicious_count  # 累積惡意事件數

        # 每秒記錄一次
        if not hasattr(self, 'cumulative_times'):
            self.cumulative_times = []
            self.cumulative_attacks = []

        if not self.cumulative_times or abs(self.cumulative_times[-1] - current_time) >= 0.9:
            self.cumulative_times.append(current_time)
            self.cumulative_attacks.append(current_cumulative)

            # 保留最近 10 分鐘
            if len(self.cumulative_times) > 600:
                self.cumulative_times.pop(0)
                self.cumulative_attacks.pop(0)

        self.ratio_ax.clear()
        self.ratio_ax.plot(self.cumulative_times, self.cumulative_attacks, 
                          'red', linewidth=3, label='惡意事件累積')
        self.ratio_ax.fill_between(self.cumulative_times, self.cumulative_attacks, 
                                  alpha=0.3, color='red')
        self.ratio_ax.set_title("惡意事件累積數（總攻擊量）", fontsize=13, fontweight='bold', color='red')
        self.ratio_ax.set_xlabel("時間 (秒)")
        self.ratio_ax.set_ylabel("累積惡意事件數")
        self.ratio_ax.grid(True, alpha=0.3)
        self.ratio_ax.legend()

        # Y 軸自動放大
        if self.cumulative_attacks:
            max_val = max(self.cumulative_attacks)
            self.ratio_ax.set_ylim(0, max(max_val * 1.1, 10))

        self.ratio_canvas.draw()
    def update_port_bar(self, frame):
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return
        top_ports = self.port_counter.most_common(5)
        if not top_ports:
            self.port_ax.clear()
            self.port_ax.text(0.5, 0.5, '無端口數據', transform=self.port_ax.transAxes, ha='center', va='center')
            self.port_canvas.draw()
            return

        ports, counts = zip(*top_ports)
        x_pos = range(len(ports))
        self.port_ax.clear()
        bars = self.port_ax.bar(x_pos, counts, color='orange', edgecolor='darkred')
        self.port_ax.set_xticks(x_pos)
        self.port_ax.set_xticklabels([str(p) for p in ports])
        self.port_ax.set_title("熱門端口 Top 5")
        self.port_ax.grid(True, axis='y', alpha=0.7)
        for bar in bars:
            h = bar.get_height()
            self.port_ax.text(bar.get_x() + bar.get_width()/2, h, f'{int(h)}', ha='center', va='bottom', fontweight='bold')
        self.port_canvas.draw()
    def update_rate_chart(self, frame):
        """即時封包速率 - 永不歪曲、永不卡死"""
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return

        current_time = time.time() - self.detect_start_time
        current_rate = self.packet_count_sec  # 這一秒的封包數

        # 每秒最多記錄一次（關鍵！避免重複或遺漏）
        if not self.timestamps or abs(self.timestamps[-1] - current_time) >= 0.9:
            self.timestamps.append(current_time)
            self.packet_rates.append(current_rate)

            # 保留最近 300 秒（5 分鐘）
            if len(self.timestamps) > 300:
                self.timestamps.pop(0)
                self.packet_rates.pop(0)

        # 完全重繪（最穩）
        self.rate_ax.clear()
        self.rate_ax.plot(self.timestamps, self.packet_rates, 'b-', linewidth=2.5)
        self.rate_ax.fill_between(self.timestamps, self.packet_rates, alpha=0.2, color='blue')
        self.rate_ax.set_title("即時封包速率", fontsize=12, fontweight='bold')
        self.rate_ax.set_xlabel("時間 (秒)")
        self.rate_ax.set_ylabel("速率 (packets/s)")
        self.rate_ax.grid(True, alpha=0.3)

        # 動態 Y 軸（永不卡死）
        if self.packet_rates:
            max_rate = max(self.packet_rates)
            self.rate_ax.set_ylim(0, max(max_rate * 1.4, 100))

        self.rate_canvas.draw()
    def update_pie_chart(self, frame):
        """攻擊類型分佈餅圖 - 永不重疊、自動拉線、超美專業版"""
        if not self.monitor_window or not self.monitor_window.winfo_exists():
            return

        label_counter = Counter()

        # 統計目前表格中所有 Label
        for table in [self.benign_table, self.malicious_table]:
            for item in table.get_children():
                values = table.item(item, "values")
                label = values[4].strip()
                label_counter[label] += 1

        if not label_counter:
            self.pie_ax.clear()
            self.pie_ax.text(0.5, 0.5, '等待數據...', transform=self.pie_ax.transAxes,
                            ha='center', va='center', fontsize=16, color='gray', alpha=0.7)
            self.pie_canvas.draw()
            return

        # 只取前 7 大類型，其餘合併為「其他」
        top_labels = label_counter.most_common(7)
        labels = [item[0] for item in top_labels]
        sizes = [item[1] for item in top_labels]

        others = sum(label_counter.values()) - sum(sizes)
        if others > 0:
            labels.append("其他")
            sizes.append(others)

        # 超美配色（資安專用）
        colors = ['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#3498db', '#e67e22', '#1abc9c', '#95a5a6']
        if len(colors) < len(labels):
            colors += ['#bdc3c7'] * (len(labels) - len(colors))

        # 關鍵！自動拉線 + 標籤外顯 + 百分比內顯
        self.pie_ax.clear()

        wedges, texts, autotexts = self.pie_ax.pie(
            sizes,
            labels=None,  # 先不畫內部標籤
            autopct=lambda pct: f'{pct:.1f}%' if pct >= 2 else '',  # 小於2% 不顯示百分比
            startangle=90,
            colors=colors,
            wedgeprops={'edgecolor': 'white', 'linewidth': 2},
            textprops={'fontsize': 10, 'color': 'white', 'fontweight': 'bold'},
            pctdistance=0.75  # 百分比靠近中心
        )

        # === 自動拉線標籤（完美解決重疊！）===
        from matplotlib.patches import ConnectionPatch
        import matplotlib.patheffects as path_effects

        # 清空舊的拉線（避免殘留）
        for artist in self.pie_ax.artists[:]:
            if isinstance(artist, ConnectionPatch):
                artist.remove()

        bbox_props = dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor="gray", alpha=0.9)

        for i, (wedge, label) in enumerate(zip(wedges, labels)):
            ang = (wedge.theta2 - wedge.theta1) / 2. + wedge.theta1
            y = np.sin(np.deg2rad(ang))
            x = np.cos(np.deg2rad(ang))

            horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
            connectionstyle = f"angle,angleA=0,angleB={ang}"
            kw = dict(arrowprops=dict(arrowstyle="-", color="black", lw=1),
                      bbox=bbox_props,
                      zorder=10,
                      va="center")

            # 只對前幾大塊拉線（避免太亂）
            if sizes[i] / sum(sizes) > 0.03:  # >3% 才拉線
                self.pie_ax.annotate(
                    f"{label} {sizes[i]/sum(sizes)*100:.1f}%",
                    xy=(x, y), xycoords='data',
                    xytext=(1.35 * np.sign(x), 1.4 * y),
                    textcoords="data",
                    horizontalalignment=horizontalalignment,
                    **kw
                )

        # 標題
        total_packets = sum(sizes)
        self.pie_ax.set_title(f"攻擊類型分佈（共 {total_packets:,} 條）",
                              fontsize=14, fontweight='bold', pad=20)

        self.pie_canvas.draw()
    def toggle_monitor_mode(self):
        """根據監控模式顯示或隱藏相關元素"""
        mode = self.monitor_mode.get()
        if mode == "local":
            self.pcap_label.grid_remove()
            self.pcap_entry.grid_remove()
            self.pcap_button.grid_remove()
            self.interface_label.grid()
            self.interface_combo.grid()
            self.log_message("切換到本機監控模式")
        elif mode == "offline":
            self.pcap_label.grid()
            self.pcap_entry.grid()
            self.pcap_button.grid()
            self.interface_label.grid_remove()
            self.interface_combo.grid_remove()
            self.log_message("切換到離線模式 (.pcap 分析)")
        save_config(self.whitelist_ips, int(self.max_threads_var.get()), mode, self.pcap_file.get(), int(self.cache_timeout_var.get()), int(self.pcap_interval_var.get()), int(self.warning_cooldown_var.get()), self.whitelist_ports, self.auto_block_var.get())
    def select_pcap_file(self):
        """瀏覽並選擇 .pcap 檔案"""
        file_path = filedialog.askopenfilename(title="選擇 .pcap 檔案", filetypes=[("PCAP files", "*.pcap *.pcapng")])
        if file_path:
            self.pcap_file.set(file_path)
            save_config(self.whitelist_ips, int(self.max_threads_var.get()), self.monitor_mode.get(), file_path, int(self.cache_timeout_var.get()), int(self.pcap_interval_var.get()), int(self.warning_cooldown_var.get()), self.whitelist_ports, self.auto_block_var.get())
            self.log_message(f"已選擇 pcap 檔案：{file_path}")
            messagebox.showinfo("成功", f"已選擇 pcap 檔案：{file_path}")
        else:
            self.log_message("未選擇 pcap 檔案")
    def show_tooltip(self, widget, text):
        """顯示工具提示"""
        x, y, _, _ = widget.bbox("insert")
        x += widget.winfo_rootx() + 25
        y += widget.winfo_rooty() + 25
        self.tooltip_window = tk.Toplevel(widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip_window, text=text, background="#ffffe0", relief="solid", borderwidth=1, font=("Segoe UI", 9))
        label.pack()
    def hide_tooltip(self, event=None):
        """隱藏工具提示"""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
    def view_hazard_logs(self):
        """顯示歷史異常報告視窗"""
        hazard_window = tk.Toplevel(self.root)
        hazard_window.title("歷史異常報告")
        hazard_window.geometry("800x600")
        hazard_frame = ttk.Frame(hazard_window, padding=10)
        hazard_frame.grid(row=0, column=0, sticky="nsew")
        hazard_window.grid_rowconfigure(0, weight=1)
        hazard_window.grid_columnconfigure(0, weight=1)
        hazard_frame.grid_rowconfigure(2, weight=1)
        hazard_frame.grid_columnconfigure(0, weight=1)
        log_select_frame = ttk.LabelFrame(hazard_frame, text="選擇日誌檔案", padding=5)
        log_select_frame.grid(row=0, column=0, sticky="ew", pady=5)
        log_select_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(log_select_frame, text="日誌檔案：").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.log_file_var = tk.StringVar()
        self.log_file_combo = ttk.Combobox(log_select_frame, textvariable=self.log_file_var, state="readonly")
        self.log_file_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(log_select_frame, text="刷新日誌列表", command=self.update_log_files).grid(row=0, column=2, padx=5, pady=5)
        self.log_file_combo.bind("<<ComboboxSelected>>", self.display_log_content)
        log_content_frame = ttk.LabelFrame(hazard_frame, text="日誌內容", padding=5)
        log_content_frame.grid(row=2, column=0, sticky="nsew", pady=5)
        log_content_frame.grid_columnconfigure(0, weight=1)
        log_content_frame.grid_rowconfigure(0, weight=1)
        self.hazard_log_text = tk.Text(log_content_frame, height=20, font=("Segoe UI", 10), wrap="none")
        self.hazard_log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll_y = ttk.Scrollbar(log_content_frame, orient="vertical", command=self.hazard_log_text.yview)
        log_scroll_y.grid(row=0, column=1, sticky="ns")
        log_scroll_x = ttk.Scrollbar(log_content_frame, orient="horizontal", command=self.hazard_log_text.xview)
        log_scroll_x.grid(row=1, column=0, sticky="ew")
        self.hazard_log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)
        self.update_log_files()
    def update_log_files(self):
        """更新日誌檔案下拉選單"""
        try:
            log_files = [f for f in os.listdir(LOG_DIR) if f.startswith('hazard_') and f.endswith('.log')]
            log_files.sort(reverse=True)
            self.log_file_combo['values'] = log_files
            if log_files:
                self.log_file_var.set(log_files[0])
                self.display_log_content()
            else:
                self.log_file_var.set("")
                self.hazard_log_text.config(state='normal')
                self.hazard_log_text.delete(1.0, tk.END)
                self.hazard_log_text.insert(tk.END, "未找到歷史異常日誌檔案")
                self.hazard_log_text.config(state='disabled')
            self.log_message("已刷新歷史異常日誌列表")
        except Exception as e:
            self.log_message(f"無法刷新日誌檔案列表：{str(e)}")
            messagebox.showerror("錯誤", f"無法刷新日誌檔案列表：{str(e)}")
    def display_log_content(self, event=None):
        """顯示選定日誌檔案的內容"""
        selected_log = self.log_file_var.get()
        if not selected_log:
            return
        try:
            log_path = os.path.join(LOG_DIR, selected_log)
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.hazard_log_text.config(state='normal')
            self.hazard_log_text.delete(1.0, tk.END)
            self.hazard_log_text.insert(tk.END, content)
            self.hazard_log_text.config(state='disabled')
            self.log_message(f"顯示日誌檔案：{selected_log}")
        except Exception as e:
            self.log_message(f"無法讀取日誌檔案 {selected_log}：{str(e)}")
            messagebox.showerror("錯誤", f"無法讀取日誌檔案 {selected_log}：{str(e)}")
    def view_blocked_ports(self):
        """顯示已封鎖端口列表視窗"""
        ports_window = tk.Toplevel(self.root)
        ports_window.title("已封鎖端口列表")
        ports_window.geometry("600x400")
        ports_frame = ttk.Frame(ports_window, padding=10)
        ports_frame.grid(row=0, column=0, sticky="nsew")
        ports_window.grid_rowconfigure(0, weight=1)
        ports_window.grid_columnconfigure(0, weight=1)
        ports_frame.grid_rowconfigure(0, weight=1)
        ports_frame.grid_columnconfigure(0, weight=1)
        self.ports_tree = ttk.Treeview(ports_frame, columns=("Port", "Protocol"), show="headings")
        self.ports_tree.heading("Port", text="端口")
        self.ports_tree.heading("Protocol", text="協議")
        self.ports_tree.column("Port", width=100)
        self.ports_tree.column("Protocol", width=100)
        self.ports_tree.grid(row=0, column=0, sticky="nsew")
        ports_scroll_y = ttk.Scrollbar(ports_frame, orient="vertical", command=self.ports_tree.yview)
        ports_scroll_y.grid(row=0, column=1, sticky="ns")
        self.ports_tree.configure(yscrollcommand=ports_scroll_y.set)
        ttk.Button(ports_frame, text="刷新列表", command=self.refresh_blocked_ports).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(ports_frame, text="解除選中端口", command=self.unblock_selected_port).grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        self.refresh_blocked_ports()
    def refresh_blocked_ports(self):
        """刷新已封鎖端口列表，從防火牆規則中獲取"""
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        try:
            cmd = 'netsh advfirewall firewall show rule name=all'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                current_rule_name = None
                current_port = None
                current_protocol = None
                for line in lines:
                    line = line.strip()
                    if line.startswith('Rule Name:') or 'IDS_Block_Port_' in line:
                        # 提取規則名稱
                        if 'IDS_Block_Port_' in line:
                            parts = line.split('IDS_Block_Port_')
                            if len(parts) > 1:
                                port_proto = parts[1].split()[0] if ' ' in parts[1] else parts[1]
                                if '_' in port_proto:
                                    port, protocol = port_proto.rsplit('_', 1)
                                    current_rule_name = line
                                    current_port = port
                                    current_protocol = protocol
                    elif line.startswith('Local Port:') or '本地端口:' in line:
                        if current_rule_name:
                            parts = line.split(':')
                            if len(parts) > 1:
                                ports_str = parts[1].strip().split(',')[0].strip()
                                if '-' in ports_str:
                                    # 範圍端口，僅顯示起始端口
                                    current_port = ports_str.split('-')[0].strip()
                                else:
                                    current_port = ports_str
                    elif line.startswith('Protocol:') or '協定:' in line:
                        if current_rule_name and current_port:
                            parts = line.split(':')
                            if len(parts) > 1:
                                protocol = parts[1].strip().split(',')[0].strip().upper()
                                if protocol in ['TCP', 'UDP']:
                                    current_protocol = protocol
                                    # 插入到樹狀視圖
                                    self.ports_tree.insert("", tk.END, values=(current_port, current_protocol))
                                    current_rule_name = None
                                    current_port = None
                                    current_protocol = None
            else:
                self.log_message(f"無法獲取防火牆規則：{result.stderr}")
        except Exception as e:
            self.log_message(f"刷新已封鎖端口列表失敗：{str(e)}")
    def unblock_selected_port(self):
        """解除選中的已封鎖端口"""
        selected = self.ports_tree.selection()
        if not selected:
            messagebox.showerror("錯誤", "請選擇一個端口")
            return
        values = self.ports_tree.item(selected[0], "values")
        port, protocol = values
        if unblock_port_local(port, protocol):
            self.log_message(f"已解除封鎖端口 {port} ({protocol})")
            messagebox.showinfo("成功", f"已解除封鎖端口 {port} ({protocol})")
            self.refresh_blocked_ports()
        else:
            self.log_message(f"無法解除封鎖端口 {port} ({protocol})")
            messagebox.showerror("錯誤", f"無法解除封鎖端口 {port} ({protocol})")
    def show_packet_details(self, event):
        """顯示選中封包的詳細資訊"""
        widget = event.widget
        selected_item = widget.selection()
        if not selected_item:
            return
        item = selected_item[0]
        values = widget.item(item, "values")
        packet_id = values[0]
        if packet_id in self.packet_details:
            details = self.packet_details[packet_id]
            detail_window = tk.Toplevel(self.root)
            detail_window.title("封包詳細資訊")
            detail_window.geometry("600x400")
            detail_frame = ttk.Frame(detail_window, padding=10)
            detail_frame.grid(row=0, column=0, sticky="nsew")
            detail_window.grid_rowconfigure(0, weight=1)
            detail_window.grid_columnconfigure(0, weight=1)
            detail_frame.grid_rowconfigure(1, weight=1)
            detail_frame.grid_columnconfigure(0, weight=1)
            basic_info = ttk.LabelFrame(detail_frame, text="基本資訊", padding=5)
            basic_info.grid(row=0, column=0, sticky="ew", pady=5)
            ttk.Label(basic_info, text=f"時間：{values[0]}").grid(row=0, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"來源 IP：{values[1]}").grid(row=1, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"目的 IP：{values[2]}").grid(row=2, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"協議：{values[3]}").grid(row=3, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"標籤：{values[4]}").grid(row=4, column=0, sticky="w", padx=5, pady=2)
            # === 新增：來源端口和目的端口 ===
            features = details.get('features', {})
            src_port = features.get('Src Port', 'N/A')
            dst_port = features.get('Dst Port', 'N/A')
            ttk.Label(basic_info, text=f"來源端口：{src_port}").grid(row=5, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(basic_info, text=f"目的端口：{dst_port}").grid(row=6, column=0, sticky="w", padx=5, pady=2)
            feature_frame = ttk.LabelFrame(detail_frame, text="特徵資訊", padding=5)
            feature_frame.grid(row=1, column=0, sticky="nsew", pady=5)
            feature_text = tk.Text(feature_frame, height=10, font=("Segoe UI", 10), wrap="none")
            feature_text.grid(row=0, column=0, sticky="nsew")
            feature_scroll_y = ttk.Scrollbar(feature_frame, orient="vertical", command=feature_text.yview)
            feature_scroll_y.grid(row=0, column=1, sticky="ns")
            feature_scroll_x = ttk.Scrollbar(feature_frame, orient="horizontal", command=feature_text.xview)
            feature_scroll_x.grid(row=1, column=0, sticky="ew")
            feature_text.configure(yscrollcommand=feature_scroll_y.set, xscrollcommand=feature_scroll_x.set)
            feature_frame.grid_columnconfigure(0, weight=1)
            feature_frame.grid_rowconfigure(0, weight=1)
            for feature, value in details['features'].items():
                feature_text.insert(tk.END, f"{feature}: {value}\n")
            feature_text.config(state='disabled')
    def update_packet_rate(self):
        """正確顯示即時封包速率（每秒重置）"""
        if self.sniffing:
            rate = getattr(self, 'packet_count_sec', 0)
            self.packet_rate.set(f"封包速率：{rate:,} packets/s")
        else:
            self.packet_rate.set("封包速率：0 packets/s")
        self.root.after(1000, self.update_packet_rate)
    def apply_max_threads(self):
        """應用新的最大執行緒數"""
        try:
            max_threads = int(self.max_threads_var.get())
            if max_threads < 1 or max_threads > 16:
                self.log_message("最大執行緒數必須在 1 到 16 之間")
                messagebox.showerror("錯誤", "最大執行緒數必須在 1 到 16 之間")
                return
            self.executor = ThreadPoolExecutor(max_workers=max_threads)
            save_config(self.whitelist_ips, max_threads, self.monitor_mode.get(), self.pcap_file.get(), int(self.cache_timeout_var.get()), int(self.pcap_interval_var.get()), int(self.warning_cooldown_var.get()), self.whitelist_ports, self.auto_block_var.get())
            self.log_message(f"最大執行緒數更新為：{max_threads}")
            messagebox.showinfo("成功", f"最大執行緒數更新為：{max_threads}")
        except ValueError:
            self.log_message("請輸入有效的最大執行緒數")
            messagebox.showerror("錯誤", "請輸入有效的最大執行緒數")
    def get_interfaces(self):
        """獲取可用網絡介面"""
        interfaces = []
        try:
            scapy_interfaces = {iface.name: iface for iface in conf.ifaces.data.values()}
            logger.debug(f"Scapy 檢測到的介面：{list(scapy_interfaces.keys())}")
            if not scapy_interfaces:
                logger.warning("Scapy 未檢測到任何介面")
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}")
            interface_map = {}
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, f"{subkey_name}\\Connection")
                    friendly_name = winreg.QueryValueEx(subkey, "Name")[0]
                    interface_map[subkey_name] = friendly_name
                    winreg.CloseKey(subkey)
                except:
                    continue
            winreg.CloseKey(key)
            winreg.CloseKey(reg)
            for guid, friendly_name in interface_map.items():
                scapy_iface_name = f"\\Device\\NPF_{guid}"
                if scapy_iface_name in scapy_interfaces:
                    interfaces.append((friendly_name, scapy_iface_name))
                else:
                    if guid in scapy_interfaces:
                        interfaces.append((friendly_name, guid))
            if not interfaces:
                logger.warning("Scapy/registry 未檢測到任何介面，嘗試使用 psutil")
                self.log_message("未檢測到任何介面，嘗試使用 psutil")
                for iface in psutil.net_if_addrs().keys():
                    interfaces.append((iface, iface))
            if interfaces:
                logger.debug(f"可用介面：{interfaces}")
                return interfaces
            else:
                logger.error("未檢測到網絡介面，請確保已安裝 Npcap 並以管理員權限運行")
                self.log_message("未檢測到網絡介面，請確保已安裝 Npcap 並以管理員權限運行")
                messagebox.showerror("錯誤", "未檢測到網絡介面，請確保已安裝 Npcap 並以管理員權限運行")
                return []
        except Exception as e:
            logger.error(f"無法獲取介面：{str(e)}")
            self.log_message(f"無法獲取介面：{str(e)}")
            messagebox.showerror("錯誤", f"無法獲取介面：{str(e)}")
            return []
    def log_message(self, message):
        """在日誌視窗中顯示訊息"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.log_tree.insert("", tk.END, values=(timestamp, "INFO", message))
            self.log_tree.see(self.log_tree.get_children()[-1])
        except AttributeError:
            logger.warning(f"無法記錄到 GUI：{message}")
    def update_interfaces(self):
        """更新網絡介面選單"""
        for _ in range(3):
            interfaces = self.get_interfaces()
            if interfaces:
                self.interface_map = {friendly_name: scapy_iface for friendly_name, scapy_iface in interfaces}
                self.interface_combo['values'] = list(self.interface_map.keys())
                if interfaces:
                    self.interface_var.set(list(self.interface_map.keys())[0])
                    self.log_message(f"檢測到 {len(interfaces)} 個網絡介面")
                    return
                else:
                    self.interface_var.set("")
                    self.log_message("無可用網絡介面")
                time.sleep(2)
        self.log_message("多次嘗試後仍無法檢測到網絡介面，請檢查 Npcap 和管理員權限")
        messagebox.showerror("錯誤", "無法檢測到網絡介面，請檢查 Npcap 和管理員權限")
    def save_whitelist(self):
        """保存白名單 IP 到配置文件"""
        whitelist_input = self.whitelist_var.get()
        self.whitelist_ips = [ip.strip() for ip in whitelist_input.split(",") if ip.strip()]
        max_threads = int(self.max_threads_var.get()) if self.max_threads_var.get().isdigit() else 4
        save_config(self.whitelist_ips, max_threads, self.monitor_mode.get(), self.pcap_file.get(), int(self.cache_timeout_var.get()), int(self.pcap_interval_var.get()), int(self.warning_cooldown_var.get()), self.whitelist_ports, self.auto_block_var.get())
        self.log_message(f"白名單 IP 已更新：{self.whitelist_ips}")
        messagebox.showinfo("成功", "白名單 IP 已保存")
    def manual_block_port(self):
        """手動封鎖指定的端口"""
        port_str = self.block_port_var.get().strip()
        protocol = self.block_port_protocol_var.get()
        if not port_str.isdigit():
            self.log_message("無效的端口號")
            messagebox.showerror("錯誤", "請輸入有效的端口號 (1-65535)")
            return
        port = int(port_str)
        if port < 1 or port > 65535:
            self.log_message("端口號超出範圍")
            messagebox.showerror("錯誤", "端口號必須在 1 到 65535 之間")
            return
        success = False
        if protocol == 'Both':
            success = block_port_local(port, 'TCP') or block_port_local(port, 'UDP')
        else:
            success = block_port_local(port, protocol)
        if success:
            self.log_message(f"已封鎖端口 {port} ({protocol})")
            messagebox.showinfo("成功", f"已封鎖端口 {port} ({protocol})")
        else:
            self.log_message(f"無法封鎖端口 {port} ({protocol})")
            messagebox.showerror("錯誤", f"無法封鎖端口 {port} ({protocol})")
    def unblock_port(self):
        """解除封鎖指定的端口"""
        port_str = self.unblock_port_var.get().strip()
        protocol = self.unblock_port_protocol_var.get()
        if not port_str.isdigit():
            self.log_message("無效的端口號")
            messagebox.showerror("錯誤", "請輸入有效的端口號")
            return
        port = int(port_str)
        if port < 1 or port > 65535:
            self.log_message("端口號超出範圍")
            messagebox.showerror("錯誤", "端口號必須在 1 到 65535 之間")
            return
        success = False
        if protocol == 'Both':
            success = unblock_port_local(port, 'TCP') or unblock_port_local(port, 'UDP')
        else:
            success = unblock_port_local(port, protocol)
        if success:
            self.log_message(f"已解除封鎖端口 {port} ({protocol})")
            messagebox.showinfo("成功", f"已解除封鎖端口 {port} ({protocol})")
        else:
            self.log_message(f"無法解除封鎖端口 {port} ({protocol})")
            messagebox.showerror("錯誤", f"無法解除封鎖端口 {port} ({protocol})")
    def clear_packet_tables(self):
        """清理封包表格和相關統計數據"""
        try:
            # 清理正常封包表格
            for item in self.benign_table.get_children():
                self.benign_table.delete(item)
            # 清理異常封包表格
            for item in self.malicious_table.get_children():
                self.malicious_table.delete(item)
            # 清理封包詳細資訊
            self.packet_details.clear()
            # 重置統計數據
            self.benign_count = 0
            self.malicious_count = 0
            self.src_ips.clear()
            self.packet_rates = []
            self.timestamps = []
            self.packet_count = 0
            self.start_time = time.time()

            # === 新增：清空圖形監控計數器 ===
            self.port_counter.clear()
            self.protocol_counts.clear()
            self.ratio_times.clear()
            self.benign_ratios.clear()
            self.malicious_ratios.clear()
            self.threat_times.clear()
            self.threat_rates.clear()

            self.log_message("已清理封包表格和相關統計資料")
            messagebox.showinfo("成功", "封包表格已清理")
        except Exception as e:
            error_msg = f"清理封包表格失敗：{str(e)}"
            logger.error(error_msg)
            self.log_message(error_msg)
            messagebox.showerror("錯誤", error_msg)
    def add_packet_to_table(self, src_ip, dst_ip, proto, label, features, packet=None,
                            force_display=False, diagnosis=None):
        """將封包資訊添加到表格並保存診斷資訊，嚴格控制表格大小"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            label = str(label).capitalize() if label else "未知"
            is_benign = label.lower() == 'benign'
            tag = 'benign' if is_benign else 'malicious'
            table = self.benign_table if is_benign else self.malicious_table

            # 協議轉換
            proto_map = {0: 'IPv6 Hop-by-Hop', 1: 'ICMP', 2: 'IGMP', 4: 'IP over IP',
                         6: 'TCP', 17: 'UDP', 41: 'IPv6'}
            proto_text = proto_map.get(proto, str(proto))

            # === 關鍵：Flood 模式下，只顯示惡意封包（大幅減輕負擔）===
            should_display = (not is_benign) or self.show_benign_var.get() or force_display
            if DROP_MODE and is_benign and not self.show_benign_var.get():
                should_display = False  # Flood 時強制不顯示良性封包

            if should_display:
                table.insert("", tk.END, values=(timestamp, src_ip, dst_ip, proto_text, label), tags=(tag,))

            # 保存詳細資訊
            packet_info = {
                'features': features or {},
                'diagnosis': diagnosis or {},
                }
            self.packet_details[timestamp] = packet_info

            # 更新統計（不管顯示與否，都計數）
            if is_benign:
                self.benign_count += 1
            else:
                self.malicious_count += 1
                hazard_logger.warning(
                    f"偵測到惡意流量 | 來源IP: {src_ip} | 目的IP: {dst_ip} | "
                    f"攻擊類型: {label} | 協議: {proto_text} | 置信度: {diagnosis.get('confidence', 0):.2%}"
                )
                if self.auto_block_var.get() and not self.processing_pcap:
                    port = features.get('Dst Port') or features.get('Src Port')
                    if port and isinstance(port, (int, float)) and 1 <= int(port) <= 65535:
                        protocol = 'TCP' if proto == 6 else 'UDP' if proto == 17 else 'TCP'
                        self.root.after(100, auto_block_suspicious_port, int(port), protocol, features)

            self.src_ips[src_ip] += 1
            self.protocol_counts[proto_text] += 1
            port = features.get('Dst Port') or features.get('Src Port')
            if port and isinstance(port, (int, float)) and port != 0:
                self.port_counter[int(port)] += 1

            # === 儲存到 detection_data ===
            record = {
                '時間': timestamp, '來源 IP': src_ip, '目的 IP': dst_ip, '協議': proto_text,
                '標籤': label, '攻擊類型': '' if is_benign else label,
                '置信度': f"{diagnosis.get('confidence', 0):.2%}" if diagnosis else 'N/A',
            }
            if 'Dst Port' in features: record['目的端口'] = features['Dst Port']
            if 'Src Port' in features: record['來源端口'] = features['Src Port']
            if 'Pkt Size Avg' in features: record['平均封包大小'] = features['Pkt Size Avg']
            self.detection_data.append(record)

            if self.session_timestamp is None and self.sniffing:
                self.session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # === 嚴格控制表格大小：批量刪除舊資料 ===
            MAX_TABLE_ROWS = 500  # 最大保留 500 筆（可自行調整）
            for tbl in [self.benign_table, self.malicious_table]:
                children = tbl.get_children()
                if len(children) > MAX_TABLE_ROWS:
                    # 一次刪除多筆，保持在上限內
                    to_delete = children[:-MAX_TABLE_ROWS + 50]  # 多刪一點避免頻繁觸發
                    for item in to_delete:
                        old_ts = tbl.item(item, "values")[0]
                        tbl.delete(item)
                        if old_ts in self.packet_details:
                            del self.packet_details[old_ts]

            # 觸發圖表更新
            self.chart_dirty.update({'rate': True, 'pie': True, 'proto': True, 'port': True})
            if not is_benign:
                self.chart_dirty.update({'threat': True, 'ratio': True})

        except Exception as e:
            logger.error(f"add_packet_to_table 發生錯誤：{str(e)}")
    def export_detection_table(self):
        """匯出當前檢測會話的表格到 CSV"""
        if not self.detection_data:
            self.log_message("無檢測數據可匯出")
            messagebox.showerror("錯誤", "無檢測數據可匯出")
            return
        try:
            timestamp = self.session_timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
            export_path = os.path.join(LOG_DIR, f"detection_table_{timestamp}.csv")
            df = pd.DataFrame(self.detection_data)
            df.to_csv(export_path, index=False, encoding='utf-8-sig')
            self.log_message(f"已匯出檢測表格到 {export_path}")
            messagebox.showinfo("成功", f"已匯出檢測表格到 {export_path}")
        except Exception as e:
            error_msg = f"匯出檢測表格失敗：{str(e)}"
            logger.error(error_msg)
            self.log_message(error_msg)
            messagebox.showerror("錯誤", error_msg)
    def search_ip_in_tables(self):
        """在表格中搜索特定 IP"""
        search_ip = self.search_ip_var.get().strip()
        if not search_ip:
            self.log_message("未輸入搜索 IP")
            messagebox.showerror("錯誤", "請輸入要搜索的 IP")
            return
        for table in [self.benign_table, self.malicious_table]:
            for item in table.get_children():
                values = table.item(item, "values")
                src_ip = values[1]
                dst_ip = values[2]
                if search_ip not in (src_ip, dst_ip):
                    table.detach(item)
        self.log_message(f"已過濾顯示包含 IP {search_ip} 的封包")
    def clear_search(self):
        """清除搜索過濾，顯示所有封包"""
        for table in [self.benign_table, self.malicious_table]:
            detached = table.get_children('')
            for item in detached:
                table.reattach(item, '', 'end')
        self.log_message("已清除搜索過濾，顯示所有封包")
    def background_sniff(self):
        """背景執行緒：只負責嗅探，把封包放入佇列"""
        interface = self.interface_var.get()
        if not interface or interface not in self.interface_map:
            self.root.after(0, lambda: self.log_message("介面選擇錯誤，無法嗅探"))
            return
        
        scapy_iface = self.interface_map[interface]
        self.log_message(f"背景嗅探啟動於：{interface}")
        
        def packet_handler(pkt):
            if not self.sniffing:
                return
            
            if packet_queue.full():
                global dropped_packets
                dropped_packets += 1
                return
            
            try:
                packet_queue.put_nowait(pkt)
            except queue.Full:
                dropped_packets += 1
        
        try:
            while self.sniffing:
                sniff(
                    iface=scapy_iface,
                    prn=packet_handler,
                    store=False,
                    timeout=1,
                    count=0
                )
        except Exception as e:
            if self.sniffing:
                self.root.after(0, lambda: self.log_message(f"背景嗅探異常：{e}"))
        finally:
            self.root.after(0, lambda: self.log_message("背景嗅探執行緒已結束"))
    def toggle_sniffing(self):
        """開始/停止檢測 - 背景嗅探 + 主執行緒處理（流暢 + 穩定 + 正確速率）"""
        global dropped_packets, DROP_MODE
        
        if not self.sniffing:
            # ============ 開始檢測 ============
            self.stop_event.clear()
            self.detect_start_time = time.time()
            dropped_packets = 0
            DROP_MODE = False
            
            # 清空佇列
            while not packet_queue.empty():
                try:
                    packet_queue.get_nowait()
                except queue.Empty:
                    break
            
            # 清空統計
            self.detection_data.clear()
            self.packet_details.clear()
            self.benign_count = 0
            self.malicious_count = 0
            self.src_ips.clear()
            self.port_counter.clear()
            self.protocol_counts.clear()
            self.session_timestamp = None
            self.packet_count_sec = 0  # 重置速率
            
            self.log_message(f"開始檢測 - 模式：{self.monitor_mode.get()}")
            self.sniffing = True
            self.start_button.config(text="停止檢測")
            
            if self.monitor_mode.get() == "offline":
                if not self.pcap_file.get():
                    messagebox.showerror("錯誤", "請先選擇 pcap 檔案")
                    self.sniffing = False
                    self.start_button.config(text="開始檢測")
                    return
                threading.Thread(target=self.process_offline_pcap).start()
            else:
                # 啟動背景嗅探執行緒
                self.sniff_thread = threading.Thread(target=self.background_sniff, daemon=False)
                self.sniff_thread.start()
                
                # 啟動主執行緒處理佇列
                self.process_queue_once()
                
        else:
            # ============ 停止檢測 ============
            self.sniffing = False
            self.stop_event.set()
            
            self.log_message("正在停止檢測...")
            self.start_button.config(state="disabled", text="停止中...")
            self.root.update_idletasks()
            
            # 取消處理任務
            if self.sniff_task:
                self.root.after_cancel(self.sniff_task)
                self.sniff_task = None
            
            # 清空佇列
            while not packet_queue.empty():
                try:
                    packet_queue.get_nowait()
                except queue.Empty:
                    break
            
            # 恢復介面（嗅探執行緒會自然結束）
            self.root.after(2000, lambda: self.start_button.config(state="normal", text="開始檢測"))
            self.root.after(2000, lambda: self.log_message("檢測已停止（背景嗅探已結束）"))
            # ============ 新增：停止檢測後合併檔案 ============
            if self.session_timestamp and (self.session_pcap_files or self.session_csv_files):
                merge_thread = threading.Thread(target=self.merge_and_cleanup_session_files, daemon=True)
                merge_thread.start()
                self.log_message("檢測停止，正在背景合併本次會話的 pcap 和 csv...")
            else:
                self.log_message("本次檢測無檔案產生，無需合併")
            if dropped_packets > 0:
                self.root.after(2000, lambda: self.log_message(f"本次檢測因抗 Flood 保護，共丟棄 {dropped_packets:,} 個封包"))


    def shutdown_executor_safe(self):
        """安全關閉 ThreadPoolExecutor（解決 CICFlowMeter 卡住問題）"""
        try:
            # 強制取消所有任務
            self.executor.shutdown(wait=False, cancel_futures=True)
        except:
            pass
        # 重新建立乾淨的執行緒池
        max_threads = int(self.max_threads_var.get() or 4)
        self.executor = ThreadPoolExecutor(max_workers=max_threads)

    def start_sniffing(self):
        interface = self.interface_var.get()
        if not interface or interface not in self.interface_map:
            self.root.after(0, lambda: messagebox.showerror("錯誤", "請選擇有效的網路介面"))
            return
        
        scapy_iface = self.interface_map[interface]
        self.log_message(f"嗅探啟動於介面：{interface} ({scapy_iface})")
        
        def packet_handler(pkt):
            if self.stop_event.is_set():
                return False  # 停止時不處理
            
            if packet_queue.full():
                global dropped_packets
                dropped_packets += 1
                return
            
            try:
                packet_queue.put_nowait(pkt)
            except queue.Full:
                dropped_packets += 1
        
        # 關鍵修復：簡單、穩定、無返回值印出
        try:
            while not self.stop_event.is_set():
                # 只嗅探 1 秒，避免卡死
                packets = sniff(
                    iface=scapy_iface,
                    prn=packet_handler,
                    store=False,
                    timeout=1,    # 必須有 timeout
                    count=0,
                    started_callback=lambda: not self.stop_event.is_set()
                )
                # 注意：這裡不要 print(packets) 或任何東西！
                # packets 會是 [] 或 list，沒封包時是 []
                
        except Exception as e:
            if not self.stop_event.is_set():
                self.root.after(0, lambda: self.log_message(f"嗅探發生異常（已安全攔截）：{e}"))
                logger.error(f"嗅探異常：{e}")
        finally:
            self.root.after(0, lambda: self.log_message("嗅探執行緒已完全結束"))
    
    def load_pcap(self):
        """在獨立執行緒中讀取 pcap 檔案並處理"""
        try:
            pcap_path = self.pcap_file.get()
            if not os.path.exists(pcap_path):
                raise FileNotFoundError(f"pcap 檔案不存在：{pcap_path}")
            self.current_pcap_packets = rdpcap(pcap_path)
            logger.debug(f"已載入 pcap 檔案：{pcap_path}，總封包數：{len(self.current_pcap_packets)}")
            self.log_message(f"已載入 pcap 檔案：{pcap_path}，總封包數：{len(self.current_pcap_packets)}")
            self.executor.submit(self.process_pcap_to_csv)
        except Exception as e:
            logger.error(f"載入 pcap 失敗：{str(e)}")
            self.log_message(f"載入 pcap 失敗：{str(e)}")
            self.root.after(0, lambda: messagebox.showerror("錯誤", f"載入 pcap 失敗：{str(e)}"))
            self.sniffing = False
            self.root.after(0, lambda: self.start_button.config(text="開始檢測"))
    def process_queue_once(self):
        """主執行緒：每 100ms 處理一次佇列（允許更高速率顯示 + 穩定 Flood + 安全清理）"""
        global dropped_packets, DROP_MODE
        
        if not self.sniffing:
            return

        # === 每秒重置速率計數 ===
        current_time = time.time()
        if not hasattr(self, 'last_rate_reset') or current_time - self.last_rate_reset >= 1.0:
            self.packet_count_sec = 0
            self.last_rate_reset = current_time

        processed = 0
        discarded_this_round = 0
        max_per_round = 200  # 提高！每 100ms 最多處理 200 筆 → 每秒最高可顯示 2000 pps

        while processed + discarded_this_round < max_per_round and not packet_queue.empty():
            try:
                packet = packet_queue.get_nowait()
                self.packet_count_sec += 1  # 所有取出的封包都計入速率

                # === 穩定 Flood 保護 ===
                if FLOOD_PROTECTION_ENABLED:
                    qsize = packet_queue.qsize()
                    if qsize > FLOOD_QUEUE_HIGH + 500 and not DROP_MODE:
                        DROP_MODE = True
                        self.root.after(0, lambda: self.log_message(
                            f"極端 Flood 偵測！啟動丟包模式（保留 {FLOOD_KEEP_RATIO*100:.1f}%）"))
                    elif qsize < FLOOD_QUEUE_LOW - 500 and DROP_MODE:
                        DROP_MODE = False
                        self.root.after(0, lambda: self.log_message("流量恢復正常，關閉丟包模式"))

                    if DROP_MODE and random.random() > FLOOD_KEEP_RATIO:
                        dropped_packets += 1
                        discarded_this_round += 1
                        continue

                # 正常處理（插入表格）
                self.packet_callback(packet)
                processed += 1

            except queue.Empty:
                break

        # === 安全清理舊封包 ===
        max_rows = 300
        for tbl in [self.benign_table, self.malicious_table]:
            try:
                children = tbl.get_children()
                if len(children) > max_rows:
                    items_to_delete = children[:len(children) - max_rows]
                    for item_id in items_to_delete:
                        try:
                            values = tbl.item(item_id, "values")
                            if values and len(values) > 0:
                                ts = values[0]
                                if ts in self.packet_details:
                                    del self.packet_details[ts]
                        except tk.TclError:
                            pass
                        try:
                            tbl.delete(item_id)
                        except tk.TclError:
                            pass
            except Exception as e:
                logger.error(f"表格清理錯誤（已忽略）：{e}")

        # 繼續下一輪
        if self.sniffing:
            self.sniff_task = self.root.after(100, self.process_queue_once)
    def _continue_offline_analysis(self):
        """接續：讀取剛剛產生的 CSV 並預測（與即時模式 100% 一致）"""
        try:
            csv_dir_abs = os.path.abspath(self.csv_dir)
            csv_files = [f for f in os.listdir(csv_dir_abs) if f.endswith(".csv")]
            if not csv_files:
                messagebox.showerror("錯誤", "未找到 CICFlowMeter 產生的 CSV 檔案")
                self._finish_offline()
                return

            csv_files.sort(key=lambda f: os.path.getmtime(os.path.join(csv_dir_abs, f)), reverse=True)
            latest_csv = os.path.join(csv_dir_abs, csv_files[0])

            # 讀檔（超強容錯）
            df = None
            for enc in ['cp950', 'utf-8-sig', 'utf-8', 'big5']:
                try:
                    df = pd.read_csv(latest_csv, encoding=enc, low_memory=False)
                    if len(df) > 0:
                        self.log_message(f"CSV 讀取成功（{enc}），共 {len(df):,} 條流量")
                        break
                except Exception as e:
                    continue

            if df is None or df.empty:
                messagebox.showerror("錯誤", "無法讀取 CSV（可能損壞或為空）")
                self._finish_offline()
                return

            # 開始逐條預測
            benign = malicious = 0
            total = len(df)
            for idx, row in df.iterrows():
                try:
                    src_ip = str(row.get('Src IP', 'N/A'))
                    dst_ip = str(row.get('Dst IP', 'N/A'))
                    proto = int(row['Protocol']) if pd.notna(row.get('Protocol')) else 0

                    features = row.to_dict()
                    flow_df = pd.DataFrame([features])
                    label, diagnosis = predict_flow(self.model, self.le, flow_df, self.training_features)
                    label_str = str(label).capitalize() if label else "Benign"
                    is_malicious = label_str.lower() != 'benign'

                    if is_malicious: malicious += 1
                    else: benign += 1

                    self.root.after(0, self.add_packet_to_table,
                                    src_ip, dst_ip, proto, label_str, features, None, False, diagnosis)

                    # 每 100 筆更新一次進度（不卡）
                    if (idx + 1) % 100 == 0 or (idx + 1) == total:
                        self.log_message(f"分析進度：{idx+1}/{total}（正常 {benign} | 惡意 {malicious}）")

                except Exception as e:
                    logger.error(f"第 {idx} 條預測錯誤: {e}")

            self.log_message(f"離線分析完成！共 {total} 條流量 → 正常 {benign} | 惡意 {malicious}")
            messagebox.showinfo("完成", f"離線分析完畢！\n\n"
                                    f"檔案：{os.path.basename(self.pcap_file.get())}\n"
                                    f"總流量數：{total:,}\n"
                                    f"正常流量：{benign:,}\n"
                                    f"惡意流量：{malicious:,}")

        except Exception as e:
            logger.exception(e)
            messagebox.showerror("分析失敗", str(e))
        finally:
            self._finish_offline()
    def update_packet_rate(self):
        if self.sniffing:
            rate = getattr(self, 'packet_count_sec', 0)
            self.packet_rate.set(f"封包速率：{rate:,} packets/s")
        else:
            self.packet_rate.set("封包速率：0 packets/s")
        self.root.after(1000, self.update_packet_rate)
    def _finish_offline(self):
        """統一收尾：恢復按鈕狀態"""
        self.sniffing = False
        self.root.after(0, lambda: self.start_button.config(text="開始檢測"))
    def packet_callback(self, packet):
        """處理每個捕獲的封包，累積到 current_pcap_packets 並根據時間間隔觸發 pcap 處理"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
    
                # 過濾無效或多播/廣播封包
                if src_ip == '0.0.0.0' or is_multicast_or_broadcast(dst_ip):
                    logger.debug(f"跳過無效或多播/廣播封包：來源={src_ip}, 目的={dst_ip}, 協議={proto}")
                    return
    
                # 檢查白名單（用戶白名單 + 動態良性 IP）
                if src_ip in self.whitelist_ips or dst_ip in self.whitelist_ips:
                    logger.debug(f"跳過白名單封包：來源={src_ip}, 目的={dst_ip}")
                    return
    
                current_time = time.time()
                # 檢查動態良性快取
                if (src_ip in self.benign_ips and current_time - self.benign_ips[src_ip] < self.cache_timeout) or \
                   (dst_ip in self.benign_ips and current_time - self.benign_ips[dst_ip] < self.cache_timeout):
                    logger.debug(f"跳過近期良性 IP 封包：來源={src_ip}, 目的={dst_ip}")
                    return
    
                # 檢查動態惡意快取
                if (src_ip in self.malicious_ips and current_time - self.malicious_ips[src_ip] < self.cache_timeout) or \
                   (dst_ip in self.malicious_ips and current_time - self.malicious_ips[dst_ip] < self.cache_timeout):
                    logger.debug(f"跳過近期惡意 IP 封包：來源={src_ip}, 目的={dst_ip}")
                    ip_key = src_ip if src_ip in self.malicious_ips else dst_ip
                    if ip_key not in self.last_warning or current_time - self.last_warning[ip_key] > self.warning_cooldown:
                        hazard_logger.warning(f"重複檢測到惡意 IP: 來源={src_ip}, 目的={dst_ip}, 時間={datetime.now()}")
                        self.last_warning[ip_key] = current_time
                    return
    
                # 根據監控模式過濾封包
                mode = self.monitor_mode.get()
                if mode != "offline":
                    if mode == "local" and not self.full_network_var.get():
                        if src_ip != self.local_ip and dst_ip != self.local_ip:
                            logger.debug(f"跳過非本機流量（全網模式未開啟）")
                            return
    
                proto_name = 'TCP' if TCP in packet else 'UDP' if UDP in packet else str(proto)
    
                # 累積封包
                self.current_pcap_packets.append(packet)
                self.packet_count += 1
                self.src_ips[src_ip] += 1
    
                # 檢查是否達到時間間隔
                current_time_ms = time.time() * 1000
                try:
                    interval_ms = int(self.pcap_interval_var.get())
                except ValueError:
                    interval_ms = 1000 # 預設 1000 毫秒
                if current_time_ms - self.last_pcap_time >= interval_ms:
                    self.executor.submit(self.process_pcap_to_csv)
                    self.last_pcap_time = current_time_ms
        
            clean_flow_state(self.flow_state)
        except Exception as e:
            logger.error(f"封包處理失敗：{str(e)}")
            self.log_message(f"封包處理失敗：{str(e)}")
            
    def merge_and_cleanup_session_files(self):
        """停止檢測後，將本次會話的所有小 pcap 和 csv 合併成單一檔案，並刪除原檔"""
        try:
            if not self.session_timestamp:
                return

            session_dir = 'C:/IDS_defense/sessions'
            os.makedirs(session_dir, exist_ok=True)

            merged_pcap_path = os.path.join(session_dir, f"session_{self.session_timestamp}.pcap")
            merged_csv_path = os.path.join(session_dir, f"session_{self.session_timestamp}.csv")

            # === 合併 pcap ===
            if self.session_pcap_files:
                merged_packets = []
                for pcap_file in self.session_pcap_files:
                    if os.path.exists(pcap_file):
                        try:
                            packets = rdpcap(pcap_file)
                            merged_packets.extend(packets)
                        except Exception as e:
                            logger.error(f"讀取 pcap 合併失敗 {pcap_file}: {e}")
                if merged_packets:
                    wrpcap(merged_pcap_path, merged_packets)
                    logger.info(f"已合併 {len(self.session_pcap_files)} 個 pcap → {merged_pcap_path}")
                    self.root.after(0, lambda: self.log_message(f"合併 pcap 完成：{os.path.basename(merged_pcap_path)}"))
                else:
                    logger.warning("合併 pcap 時無有效封包")

            # === 合併 csv ===
            if self.session_csv_files:
                merged_df = pd.DataFrame()
                for csv_file in self.session_csv_files:
                    if os.path.exists(csv_file):
                        try:
                            # 多編碼嘗試讀取（與原程式一致）
                            df = None
                            for enc in ['cp950', 'utf-8-sig', 'utf-8', 'big5']:
                                try:
                                    df = pd.read_csv(csv_file, encoding=enc, low_memory=False)
                                    if len(df) > 0:
                                        break
                                except:
                                    continue
                            if df is not None and len(df) > 0:
                                merged_df = pd.concat([merged_df, df], ignore_index=True)
                        except Exception as e:
                            logger.error(f"讀取 csv 合併失敗 {csv_file}: {e}")
                if len(merged_df) > 0:
                    merged_df.to_csv(merged_csv_path, index=False, encoding='utf-8-sig')
                    logger.info(f"已合併 {len(self.session_csv_files)} 個 csv → {merged_csv_path}")
                    self.root.after(0, lambda: self.log_message(f"合併 csv 完成：{os.path.basename(merged_csv_path)}"))
                else:
                    logger.warning("合併 csv 時無有效資料")

            # === 刪除原始零散檔案 ===
            deleted_count = 0
            for file_list, name in [(self.session_pcap_files, "pcap"), (self.session_csv_files, "csv")]:
                for f in file_list:
                    if os.path.exists(f):
                        try:
                            os.remove(f)
                            deleted_count += 1
                            logger.info(f"已刪除零散 {name} 檔案: {f}")
                        except Exception as e:
                            logger.warning(f"刪除 {name} 檔案失敗 {f}: {e}")
            self.root.after(0, lambda: self.log_message(f"已清理 {deleted_count} 個零散檔案"))

            # === 重置列表 ===
            self.session_pcap_files.clear()
            self.session_csv_files.clear()

        except Exception as e:
            logger.error(f"合併與清理過程發生錯誤：{str(e)}")
            self.root.after(0, lambda: self.log_message(f"合併檔案失敗：{str(e)}"))
    def process_pcap_to_csv(self):
        """將累積的封包儲存為 .pcap 並轉換為 .csv（防 Flood 空檔案 + 更穩定）"""
        # === 若無封包，直接返回 ===
        if not self.current_pcap_packets:
            logger.debug("沒有封包需要處理為 .pcap")
            return

        # === Flood 保護後常見情況：封包被大量丟棄，只剩極少或零筆 ===
        current_packet_count = len(self.current_pcap_packets)
        if current_packet_count < 1:  # 少於 1 筆視為無效批次（可自行調整）
            logger.info(f"本批次封包過少（{current_packet_count} 筆），疑似 Flood 丟包過多，直接捨棄不產生 CSV")
            self.current_pcap_packets.clear()  # 清空釋放記憶體
            return

        # === 防止重複處理 ===
        if getattr(self, 'processing_pcap', False):
            logger.debug("已在處理 pcap，略過本次呼叫")
            return

        self.processing_pcap = True
        pcap_filename = None
        try:
            # === 步驟1：確保目錄可寫入 ===
            for dir_path in [self.pcap_dir, self.csv_dir]:
                dir_abs = os.path.abspath(dir_path)
                os.makedirs(dir_abs, exist_ok=True)
                if not os.access(dir_abs, os.W_OK):
                    logger.error(f"目錄無寫入權限: {dir_abs}")
                    return

            # === 步驟2：儲存 PCAP ===
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = os.path.normpath(os.path.join(self.pcap_dir, f"flow_{timestamp}.pcap"))
            wrpcap(pcap_filename, self.current_pcap_packets)

            # 注意：此時已清空列表，所以用變數記錄實際封包數
            logger.info(f"PCAP 已儲存: {pcap_filename} ({current_packet_count} packets)")
            self.current_pcap_packets.clear()  # 清空釋放記憶體
            # 記錄本次會話的 pcap 檔案（用於停止後合併）
            if self.sniffing and hasattr(self, 'session_pcap_files'):
                self.session_pcap_files.append(pcap_filename)
            # === 步驟3：執行 CICFlowMeter ===
            csv_dir_abs = os.path.abspath(self.csv_dir)
            cmd = f'cfm.bat "{pcap_filename}" "{csv_dir_abs}"'
            logger.info(f"執行 CICFlowMeter: {cmd}")

            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=90)
            if result.returncode != 0:
                err_msg = result.stderr.decode('cp950', errors='replace')
                logger.error(f"CICFlowMeter 失敗 (code {result.returncode}): {err_msg}")
                return

            # === 步驟4：等待並讀取最新 CSV ===
            deadline = time.time() + 15
            csv_path = None
            while time.time() < deadline:
                csv_files = [f for f in os.listdir(csv_dir_abs) if f.endswith(".csv")]
                if csv_files:
                    csv_files.sort(key=lambda f: os.path.getmtime(os.path.join(csv_dir_abs, f)), reverse=True)
                    candidate = os.path.join(csv_dir_abs, csv_files[0])
                    if os.path.getsize(candidate) > 100:  # 至少有點內容
                        csv_path = candidate
                        break
                time.sleep(0.5)

            if not csv_path:
                logger.error("未找到有效的 CSV 檔案（CICFlowMeter 可能未產生）")
                return

            # === 步驟5：多編碼嘗試讀取 CSV（超強容錯）===
            df = None
            for encoding in ['cp950', 'big5', 'utf-8-sig', 'utf-8', 'gbk']:
                try:
                    logger.debug(f"嘗試用 {encoding} 讀取 CSV...")
                    df = pd.read_csv(csv_path, encoding=encoding, low_memory=False, on_bad_lines='skip')
                    if len(df) > 0:
                        logger.info(f"CSV 讀取成功！使用編碼: {encoding}，共 {len(df)} 條流量")
                        break
                except Exception as e:
                    logger.debug(f"{encoding} 讀取失敗: {e}")

            if df is None or df.empty:
                logger.error("所有編碼讀取失敗，CSV 可能損壞或為空")
                # 最後強制手段
                try:
                    df = pd.read_csv(csv_path, encoding='cp950', errors='ignore', low_memory=False)
                    logger.warning("已用 cp950 + errors='ignore' 強制讀取（可能有亂碼）")
                except Exception as e:
                    logger.error(f"最終強制讀取失敗，放棄此批次: {e}")
                    return

            logger.info(f"載入 CSV 成功: {csv_path} ({len(df)} 條流量)")
            # 記錄本次會話的 csv 檔案（用於停止後合併）
            if self.sniffing and hasattr(self, 'session_csv_files'):
                self.session_csv_files.append(csv_path)
            # === 步驟6：逐條預測並顯示（防崩潰）===
            for idx, row in df.iterrows():
                try:
                    src_ip = str(row.get('Src IP', 'Unknown'))
                    dst_ip = str(row.get('Dst IP', 'Unknown'))
                    proto = int(row.get('Protocol', 0)) if pd.notna(row.get('Protocol')) else 0
                    features = row.to_dict()

                    # 安全預測
                    label, diagnosis = "unknown", {"error": "predict failed"}
                    try:
                        flow_df = pd.DataFrame([features])
                        label, diagnosis = predict_flow(self.model, self.le, flow_df, self.training_features)
                        if label is None:
                            label = "unknown"
                    except Exception as e:
                        logger.warning(f"第 {idx} 條流量預測失敗: {e}")

                    # label 格式統一
                    if isinstance(label, (list, np.ndarray)):
                        label = label[0] if len(label) > 0 else "unknown"
                    if isinstance(label, (int, np.int64)):
                        label = self.le.inverse_transform([label])[0] if hasattr(self, 'le') else "unknown"
                    label_str = str(label).capitalize()
                    is_malicious = label_str.lower() != 'benign'

                    # 加入表格（使用 root.after 避免跨執行緒問題）
                    self.root.after(0, self.add_packet_to_table,
                                    src_ip, dst_ip, proto, label_str, features, None,
                                    is_malicious, diagnosis)

                except Exception as e:
                    logger.error(f"處理第 {idx} 條流量時發生未預期錯誤: {e}")
                    continue

        except Exception as e:
            logger.error(f"process_pcap_to_csv 嚴重錯誤: {e}")
        finally:
            self.processing_pcap = False
class TreeviewHandler(logging.Handler):
    """自訂日誌處理器，將日誌顯示在 ttk.Treeview 表格中"""
    def __init__(self, treeview):
        super().__init__()
        self.treeview = treeview
    def emit(self, record):
        msg = self.format(record)
        parts = msg.split(' - ', 2)
        if len(parts) == 3:
            timestamp, level, message = parts
        else:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            level = record.levelname
            message = msg
        self.treeview.insert("", tk.END, values=(timestamp, level, message))
        self.treeview.see(self.treeview.get_children()[-1])
        self.treeview.update()
        # 更新統計
        app = None  # 需要傳入 app 實例來更新 stats，簡化為全局或事件
def main():
    
    root = tk.Tk()
    responsive = ResponsiveDesign(root)
    app = IDSApp(root)
    root.mainloop()
if __name__ == "__main__":
    main()
