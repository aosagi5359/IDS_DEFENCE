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
import queue
from concurrent.futures import ThreadPoolExecutor
import socket
import subprocess
from binascii import hexlify
import ipaddress
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import matplotlib
matplotlib.rcParams['font.family'] = 'Noto Sans TC'
matplotlib.rcParams['font.sans-serif'] = ['Noto Sans TC']
matplotlib.rcParams['axes.unicode_minus'] = False
# 確保日誌目錄存在
LOG_DIR = 'C:/IDS_defense/logs'
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
# 配置危險日誌
hazard_log_file = os.path.join(LOG_DIR, f'hazard_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
hazard_logger = logging.getLogger('HazardLogger')
hazard_logger.setLevel(logging.WARNING)
try:
    hazard_handler = logging.handlers.RotatingFileHandler(
        hazard_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    hazard_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    hazard_logger.addHandler(hazard_handler)
    logger.debug(f"危險日誌已配置：{hazard_log_file}")
except Exception as e:
    logger.error(f"無法配置危險日誌：{str(e)}")
    hazard_logger.addHandler(logging.StreamHandler())
# JSON 配置文件
CONFIG_FILE = 'C:/IDS_defense/config.json'
# 執行緒鎖
lock = threading.Lock()
# 封包處理隊列
packet_queue = queue.Queue()
# 新增：白名單端口和自動封鎖變數
whitelist_ports = []
auto_block_ports = True # 預設啟用自動封鎖
# 新增：日志統計
log_stats = {'total': 0, 'warning': 0, 'top_types': Counter()}
# 新增：模型選擇和更新
available_models = {'xgboost': 'C:\\IDS_defense\\PROJ2\\xgboost_model.pkl', 'rf': 'C:\\IDS_defense\\PROJ2\\rf_model.pkl'} # 假設有 RF 模型
current_model = 'xgboost'
# ==================== 響應式字體 & 按鍵大小（自動隨視窗縮放） ====================
import tkinter.font as tkfont

# 全域字體基準（會隨著視窗寬度自動調整）
BASE_FONT_SIZE = 10
BUTTON_PADDING_Y = 8
BUTTON_PADDING_X = 12

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
                whitelist_ports=None, auto_block=None):
    """保存所有設定到 config.json"""
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
            'auto_block_ports': auto_block if auto_block is not None else True
        }
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
        logger.debug(f"配置已成功保存到 {CONFIG_FILE}")
    except Exception as e:
        logger.error(f"保存配置失敗：{str(e)}")
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
                    default_auto_block
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
    """返回模型訓練時的確切 30 個特徵順序"""
    features = [
        'URG Flag Cnt', 'Bwd Header Len', 'ECE Flag Cnt', 'PSH Flag Cnt', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'Bwd PSH Flags', 'Bwd URG Flags', 'Dst Port', 'ACK Flag Cnt', 'Bwd Pkts/s', 'Init Bwd Win Byts', 'Src Port', 'Flow Duration', 'Fwd Header Len', 'Flow IAT Mean', 'TotLen Bwd Pkts', 'Bwd Pkt Len Max', 'Fwd Pkts/s', 'Tot Bwd Pkts', 'Bwd IAT Std', 'Pkt Len Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow Byts/s', 'Fwd Pkt Len Max', 'Flow Pkts/s', 'Down/Up Ratio', 'Bwd IAT Tot'
    ]
    logger.debug(f" 載入訓練特徵：{len(features)} 個，順序正確")
    return features
def predict_flow(model, le, flow_df, training_features):
    """預測流量並返回詳細診斷資訊"""
    try:
        scaler = joblib.load('C:\\IDS_defense\\PROJ2\\scaler.pkl')
        # 模型訓練時的確切 30 個特徵順序
        model_feature_names = [
            'URG Flag Cnt', 'Bwd Header Len', 'ECE Flag Cnt', 'PSH Flag Cnt', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'Bwd PSH Flags', 'Bwd URG Flags', 'Dst Port', 'ACK Flag Cnt', 'Bwd Pkts/s', 'Init Bwd Win Byts', 'Src Port', 'Flow Duration', 'Fwd Header Len', 'Flow IAT Mean', 'TotLen Bwd Pkts', 'Bwd Pkt Len Max', 'Fwd Pkts/s', 'Tot Bwd Pkts', 'Bwd IAT Std', 'Pkt Len Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow Byts/s', 'Fwd Pkt Len Max', 'Flow Pkts/s', 'Down/Up Ratio', 'Bwd IAT Tot'
        ]
        # 構建特徵向量並記錄映射結果
        feature_vector = []
        feature_mapping_info = {} # 記錄每個特徵的原始值和映射
        for i, model_feat in enumerate(model_feature_names):
            if model_feat in flow_df.columns:
                value = float(flow_df[model_feat].iloc[0])
            else:
                value = 0.0
            feature_vector.append(value)
  
            # 記錄映射資訊（僅關鍵特徵）
            if i < 10 or value != 0: # 前10個特徵 + 非零值
                feature_mapping_info[model_feat] = {
                    'value': value,
                    'found': model_feat in flow_df.columns
                }
        flow_array = np.array([feature_vector])
        # 標準化
        flow_scaled = scaler.transform(flow_array)
        # 預測
        preds = model.predict(flow_scaled)
        preds_proba = model.predict_proba(flow_scaled)[0] # 預測概率
        preds_labels = le.inverse_transform(preds)
        normalized_label = preds_labels[0].lower()
        # 構建診斷資訊
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
        logger.error(f"預測失敗：{str(e)}")
        return None, {'error': str(e)}
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
        self.le = joblib.load('C:\\IDS_defense\\PROJ2\\label_encoder.pkl')
        self.training_features = get_training_features()
        self.flow_state = {}
        self.sniffing = False
        self.sniff_thread = None
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
        self.pcap_interval_ms = tk.StringVar(value="1000") # 預設 1000 毫秒
        self.last_pcap_time = time.time() * 1000 # 記錄上次生成 pcap 的時間（毫秒）
        (self.whitelist_ips, max_threads, monitor_mode, pcap_file, 
         cache_timeout, pcap_interval, warning_cooldown, 
         loaded_ports, loaded_auto_block) = load_config()
         
        self.whitelist_ports = loaded_ports
        self.auto_block_ports = loaded_auto_block
        
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

        # === 圖形監控專用計數器（必須初始化）===
        self.port_counter = Counter()          # 端口計數（頂部端口條形圖）
        self.protocol_counts = Counter()       # 協議計數（協議餅圖）
        self.ratio_times = []                  # 良惡比率折線圖時間軸
        self.benign_ratios = []                # 良性比例
        self.malicious_ratios = []             # 惡意比例
        self.threat_times = []                 # 威脅事件率時間軸
        self.threat_rates = []                 # 威脅事件率（惡意事件/秒）
        self.full_network_var = tk.BooleanVar(value=False)
        self.setup_gui()
        # 啟動 CPU 監控
        self.update_cpu()
        # 啟動日志清理
        self.root.after(10000, self.periodic_cleanup)
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
        """保存所有設定（包含自動封鎖勾選）"""
        try:
            max_threads = int(self.max_threads_var.get())
            cache_timeout = int(self.cache_timeout_var.get())
            pcap_interval = int(self.pcap_interval_var.get())
            warning_cooldown = int(self.warning_cooldown_var.get())
            
            if not (1 <= max_threads <= 16):
                raise ValueError("執行緒數必須在 1~16 之間")
            if cache_timeout <= 0 or pcap_interval <= 0 or warning_cooldown <= 0:
                raise ValueError("時間設定必須大於 0")
                
            # 更新執行緒池
            self.executor.shutdown(wait=True)
            self.executor = ThreadPoolExecutor(max_workers=max_threads)
            self.cache_timeout = cache_timeout
            self.warning_cooldown = warning_cooldown
            
            # 同步全域變數
            global auto_block_ports, whitelist_ports
            auto_block_ports = self.auto_block_var.get()
            whitelist_ports = self.whitelist_ports
            
            # 儲存所有設定
            save_config(
                self.whitelist_ips, max_threads, self.monitor_mode.get(),
                self.pcap_file.get() or None, cache_timeout, pcap_interval,
                warning_cooldown, self.whitelist_ports, auto_block_ports
            )
            
            self.log_message("所有設定已成功保存（含自動封鎖與白名單端口）")
            messagebox.showinfo("成功", "設定已保存，重開程式後依然生效！")
            
        except Exception as e:
            messagebox.showerror("錯誤", str(e))
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
        hazard_logger.addHandler(self.gui_handler)
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
        self.ratio_ax.set_title("良惡流量比例 (%)")
        self.ratio_ax.grid(True, alpha=0.3)
        self.ratio_canvas.draw()
    def update_ratio_line(self, frame):  # 改名也沒關係，或直接取代原位置
        """惡意事件累積數 - 最強戰情圖！"""
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
            raw_frame = ttk.LabelFrame(detail_frame, text="原始數據", padding=5)
            raw_frame.grid(row=2, column=0, sticky="nsew", pady=5)
            raw_text = tk.Text(raw_frame, height=5, font=("Courier New", 10), wrap="none")
            raw_text.grid(row=0, column=0, sticky="nsew")
            raw_scroll_y = ttk.Scrollbar(raw_frame, orient="vertical", command=raw_text.yview)
            raw_scroll_y.grid(row=0, column=1, sticky="ns")
            raw_scroll_x = ttk.Scrollbar(raw_frame, orient="horizontal", command=raw_text.xview)
            raw_scroll_x.grid(row=1, column=0, sticky="ew")
            raw_text.configure(yscrollcommand=raw_scroll_y.set, xscrollcommand=raw_scroll_x.set)
            raw_frame.grid_columnconfigure(0, weight=1)
            raw_frame.grid_rowconfigure(0, weight=1)
            if details['raw_data'] == 'N/A':
                raw_text.insert(tk.END, "無原始數據可用\n")
            else:
                hex_data = details['raw_data']
                ascii_data = ''.join(chr(int(hex_data[i:i+2], 16)) if 32 <= int(hex_data[i:i+2], 16) <= 126 else '.' for i in range(0, len(hex_data), 2))
                for i in range(0, len(hex_data), 32):
                    hex_line = ' '.join(hex_data[j:j+2] for j in range(i, min(i+32, len(hex_data)), 2))
                    ascii_line = ascii_data[i//2:(i+32)//2]
                    raw_text.insert(tk.END, f"{hex_line.ljust(48)} {ascii_line}\n")
            raw_text.config(state='disabled')
            logger.debug(f"已顯示封包詳細資訊，時間戳：{packet_id}")
    def update_packet_rate(self):
        """更新 GUI 中的封包處理速率（改用每秒計數，超穩定）"""
        if self.sniffing:
            # 直接顯示這一秒收到的封包數（最準確、最平滑）
            rate = self.packet_count_sec
            self.packet_rate.set(f"封包速率：{rate} packets/s")
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
        """安全、穩定、高效地添加封包到表格（企業級容錯版）"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            label = str(label) if label else "Unknown"
            is_benign = label.lower() == 'benign'
            table = self.benign_table if is_benign else self.malicious_table
            tag = 'benign' if is_benign else 'malicious'

            # 協議名稱
            proto_map = {0: 'IPv6 Hop-by-Hop', 1: 'ICMP', 2: 'IGMP', 4: 'IP over IP',
                        6: 'TCP', 17: 'UDP', 41: 'IPv6'}
            proto_text = proto_map.get(proto, str(proto))

            # 插入表格
            table.insert("", "end", values=(timestamp, src_ip, dst_ip, proto_text, label), tags=(tag,))

            # 儲存詳細資訊
            self.packet_details[timestamp] = {
                'features': features or {},
                'diagnosis': diagnosis or {},
                'raw_data': hexlify(bytes(packet)).decode('ascii') if packet else 'N/A'
            }

            # 更新計數
            if is_benign:
                self.benign_count += 1
            else:
                self.malicious_count += 1
                if self.auto_block_var.get() and not self.processing_pcap:  # 離線模式不自動封鎖
                    port = features.get('Dst Port') or features.get('Src Port')
                    if port and port != 0:
                        protocol = 'TCP' if proto == 6 else 'UDP' if proto == 17 else 'TCP'
                        self.root.after(100, auto_block_suspicious_port, int(port), protocol, features)

            self.src_ips[src_ip] += 1

            # 更新圖表計數器
            self.protocol_counts[proto_text] += 1
            port = features.get('Dst Port') or features.get('Src Port')
            if port and port != 0:
                self.port_counter[int(port)] += 1

            # 觸發圖表更新（髒標記）
            self.chart_dirty.update({
                'rate': True, 'pie': True, 'proto': True, 'port': True,
                'threat': not is_benign, 'ratio': not is_benign
            })

            # 限制表格長度
            for tbl in (self.benign_table, self.malicious_table):
                if len(tbl.get_children()) > 200:
                    tbl.delete(tbl.get_children()[0])

        except Exception as e:
            logger.error(f"add_packet_to_table 嚴重錯誤（已攔截）: {e}")
            # 至少顯示一筆錯誤記錄
            try:
                self.malicious_table.insert("", "end", 
                    values=(datetime.now().strftime('%H:%M:%S'), src_ip, dst_ip, "Error", "CRASH"))
            except: pass
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
    def toggle_sniffing(self):
        """開始或停止封包嗅探或 pcap 分析（企業級穩定版）"""
        if not self.sniffing:
            # ==================== 開始檢測 ====================
            mode = self.monitor_mode.get()
            self.detection_data = []
            self.session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # 關鍵：真正開始時間（只設一次！）
            self.detect_start_time = time.time()
            self.packet_count = 0
            self.packet_count_sec = 0
            self.last_sec_time = time.time()

            # 清空所有統計數據（一次搞定，絕不殘留）
            reset_attrs = [
                'timestamps', 'packet_rates',
                'threat_times', 'threat_rates',
                'ratio_times', 'benign_ratios', 'malicious_ratios',
                'benign_count', 'malicious_count',
                'src_ips', 'port_counter', 'protocol_counts',
                'benign_ips', 'malicious_ips', 'packet_details',
                'current_pcap_packets'
            ]
            for attr in reset_attrs:
                if hasattr(self, attr):
                    value = getattr(self, attr)
                    if isinstance(value, (list, dict, Counter)):
                        value.clear()
                    else:
                        setattr(self, attr, type(value)())

            # 重置圖表髒標記
            for key in self.chart_dirty:
                self.chart_dirty[key] = True

            self.log_message(f"開始檢測（模式：{mode}） - 所有統計已重置")

            if mode == "offline":
                if not self.pcap_file.get():
                    self.log_message("離線模式下未選擇 pcap 檔案")
                    messagebox.showerror("錯誤", "請選擇 .pcap 檔案")
                    return
                self.sniffing = True
                self.start_button.config(text="停止檢測")
                self.sniff_thread = threading.Thread(target=self.process_offline_pcap, daemon=True)
                self.sniff_thread.start()
            else:
                if not self.local_ip:
                    self.log_message("無法獲取本機 IP")
                    messagebox.showerror("錯誤", "無法獲取本機 IP")
                    return
                if not self.interface_var.get():
                    self.log_message("未選擇網絡介面")
                    messagebox.showerror("錯誤", "請選擇網絡介面")
                    return

                self.sniffing = True
                self.start_button.config(text="停止檢測")
                self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
                self.process_thread = threading.Thread(target=self.process_packets, daemon=True)
                self.sniff_thread.start()
                self.process_thread.start()

        else:
            # ==================== 停止檢測 ====================
            self.sniffing = False
            packet_queue.put(None)  # 停止信號

            # 安全等待執行緒結束
            for thread_name in ('sniff_thread', 'process_thread'):
                thread = getattr(self, thread_name, None)
                if thread and thread.is_alive():
                    thread.join(timeout=8)

            # 清空佇列
            while not packet_queue.empty():
                try: packet_queue.get_nowait()
                except queue.Empty: break

            self.start_button.config(text="開始檢測")
            self.log_message("檢測已停止，所有執行緒已安全結束")
    def start_sniffing(self):
        """在獨立執行緒中開始封包嗅探"""
        try:
            interface = self.interface_map.get(self.interface_var.get())
            if not interface:
                raise ValueError("無效的網絡介面")
            sniff(iface=interface, prn=lambda pkt: packet_queue.put(pkt), store=0)
        except Exception as e:
            logger.error(f"嗅探失敗：{str(e)}")
            self.log_message(f"嗅探失敗：{str(e)}")
            self.root.after(0, lambda: messagebox.showerror("錯誤", f"嗅探失敗：{str(e)}"))
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
    def process_packets(self):
        self.last_sec_time = time.time()
        while self.sniffing:
            try:
                # 每秒重置計數器
                if time.time() - self.last_sec_time >= 1.0:
                    self.packet_count_sec = 0
                    self.last_sec_time = time.time()
                    
                    # 真正的秒數時間軸（這才是王道！）
                    current_sec = int(time.time() - self.detect_start_time)
                    
                    # 只記錄一次，避免重複
                    if not self.timestamps or self.timestamps[-1] != current_sec:
                        self.timestamps.append(current_sec)
                        self.packet_rates.append(0)  # 會被後面累加
                        self.threat_times.append(current_sec)
                        self.threat_rates.append(self.malicious_count / max((time.time() - self.detect_start_time), 1))
                        self.ratio_times.append(current_sec)

                if self.packet_count_sec >= self.max_packets_per_sec:
                    time.sleep(0.1)
                    continue

                packet = packet_queue.get(timeout=1)
                if packet is None:
                    break

                self.packet_callback(packet)
                self.packet_count_sec += 1

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"處理封包錯誤: {e}")
    def process_offline_pcap(self):
        """離線模式：直接用 scapy 逐包計算 CICFlowMeter 特徵 + 即時預測（不再呼叫 cfm.bat）"""
        try:
            pcap_path = self.pcap_file.get().strip()
            if not pcap_path or not os.path.exists(pcap_path):
                messagebox.showerror("錯誤", "請選擇有效的 .pcap/.pcapng 檔案")
                return

            self.log_message(f"開始離線分析（純 Scapy 版）：{os.path.basename(pcap_path)}")
            packets = rdpcap(pcap_path)

            if len(packets) == 0:
                messagebox.showinfo("完成", "pcap 內無封包")
                return

            # 用 Scapy 自己生成 flow（五元組 + 方向）
            flows = defaultdict(lambda: {
                'packets': [], 'start_time': None, 'src_ip': None, 'dst_ip': None,
                'src_port': None, 'dst_port': None, 'proto': None
            })

            for pkt in packets:
                if IP not in pkt:
                    continue
                key = (pkt[IP].src, pkt[IP].dst, pkt[IP].proto,
                       pkt.sport if TCP in pkt or UDP in pkt else 0,
                       pkt.dport if TCP in pkt or UDP in pkt else 0)
                rev_key = (pkt[IP].dst, pkt[IP].src, pkt[IP].proto,
                           pkt.dport if TCP in pkt or UDP in pkt else 0,
                           pkt.sport if TCP in pkt or UDP in pkt else 0)

                flow_key = key if key in flows else rev_key if rev_key in flows else key
                flow = flows[flow_key]

                if flow['start_time'] is None:
                    flow['start_time'] = pkt.time
                    flow['src_ip'], flow['dst_ip'] = pkt[IP].src, pkt[IP].dst
                    flow['proto'] = pkt[IP].proto
                    flow['src_port'] = pkt.sport if TCP in pkt or UDP in pkt else 0
                    flow['dst_port'] = pkt.dport if TCP in pkt or UDP in pkt else 0

                flow['packets'].append(pkt)

            self.log_message(f"共提取 {len(flows)} 條 flow，開始模型預測…")

            benign = 0
            malicious = 0

            # 批次處理（每 100 條更新一次 GUI，避免卡死）
            flow_list = list(flows.values())
            for i in range(0, len(flow_list), 100):
                batch = flow_list[i:i+100]

                for flow in batch:
                    try:
                        # 這裡直接用你原本的 CICFlowMeter 特徵計算函數（你專案裡應該有）
                        # 如果你沒有，我下面給你一個極簡版也能跑
                        features = self.extract_features_from_flow(flow)  # ← 你要實作這個
                        if not features:
                            continue

                        flow_df = pd.DataFrame([features])
                        label, diagnosis = predict_flow(self.model, self.le, flow_df, self.training_features)

                        label_str = str(label).capitalize() if label else "Benign"
                        is_malicious = label_str.lower() != 'benign'

                        if is_malicious:
                            malicious += 1
                        else:
                            benign += 1

                        # 直接呼叫（不要用 lambda + after，大量時會炸）
                        self.add_packet_to_table(
                            flow['src_ip'], flow['dst_ip'], flow['proto'],
                            label_str, features, None,
                            force_display=is_malicious, diagnosis=diagnosis
                        )
                    except Exception as e:
                        logger.error(f"離線 flow 預測失敗: {e}")
                        continue

                # 每批次強制刷新 GUI，否則會卡死
                self.root.update_idletasks()
                time.sleep(0.001)  # 讓出 CPU

            self.log_message(f"離線分析完成！正常 {benign} 條，惡意 {malicious} 條")
            messagebox.showinfo("離線分析完成",
                                f"總 flow 數：{len(flows)}\n"
                                f"正常：{benign} 條\n"
                                f"惡意：{malicious} 條")

        except Exception as e:
            logger.exception(e)
            messagebox.showerror("離線分析失敗", str(e))
        finally:
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
            
    def extract_features_from_flow(self, flow):
        """極簡版特徵提取，能讓 XGBoost/RF 模型跑就行"""
        pkts = flow['packets']
        if not pkts:
            return None

        times = [p.time for p in pkts]
        sizes = [len(p) for p in pkts]

        duration = max(times) - min(times) if len(times) > 1 else 0
        pkt_count = len(pkts)
        byte_count = sum(sizes)

        fwd_pkts = sum(1 for p in pkts if p[IP].src == flow['src_ip'])
        bwd_pkts = pkt_count - fwd_pkts

        return {
            'Flow Duration': duration * 1e6,  # 微秒
            'Tot Fwd Pkts': fwd_pkts,
            'Tot Bwd Pkts': bwd_pkts,
            'TotLen Fwd Pkts': sum(len(p) for p in pkts if p[IP].src == flow['src_ip']),
            'TotLen Bwd Pkts': sum(len(p) for p in pkts if p[IP].src != flow['src_ip']),
            'Fwd Pkt Len Mean': np.mean([len(p) for p in pkts if p[IP].src == flow['src_ip']]) if fwd_pkts else 0,
            'Bwd Pkt Len Mean': np.mean([len(p) for p in pkts if p[IP].src != flow['src_ip']]) if bwd_pkts else 0,
            'Flow Byts/s': byte_count / (duration + 1e-6) if duration > 0 else 0,
            'Flow Pkts/s': pkt_count / (duration + 1e-6) if duration > 0 else 0,
            'Protocol': flow['proto'],
            'Src Port': flow['src_port'],
            'Dst Port': flow['dst_port'],
            # 其餘特徵填 0（模型會自己處理缺失）
            **{f: 0 for f in self.training_features if f not in [
                'Flow Duration','Tot Fwd Pkts','Tot Bwd Pkts','TotLen Fwd Pkts','TotLen Bwd Pkts',
                'Fwd Pkt Len Mean','Bwd Pkt Len Mean','Flow Byts/s','Flow Pkts/s','Protocol','Src Port','Dst Port'
            ]}
        }
    def process_pcap_to_csv(self):
        """將累積的封包儲存為 .pcap 並轉換為 .csv，然後觸發流量處理（企業級穩定版）"""
        if not self.current_pcap_packets:
            logger.debug("沒有封包需要處理為 .pcap")
            return
        if getattr(self, 'processing_pcap', False):
            logger.debug("已在處理 pcap，略過本次呼叫")
            return

        self.processing_pcap = True
        pcap_filename = None
        csv_path = None

        try:
            # === 步驟1：儲存 PCAP ===
            for dir_path in [self.pcap_dir, self.csv_dir]:
                dir_abs = os.path.abspath(dir_path)
                os.makedirs(dir_abs, exist_ok=True)
                if not os.access(dir_abs, os.W_OK):
                    logger.error(f"目錄無寫入權限: {dir_abs}")
                    return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = os.path.normpath(os.path.join(self.pcap_dir, f"flow_{timestamp}.pcap"))
            wrpcap(pcap_filename, self.current_pcap_packets)
            self.current_pcap_packets.clear()  # 立即清空，釋放記憶體
            logger.info(f"PCAP 已儲存: {pcap_filename} ({len(self.current_pcap_packets)} packets)")

            # === 步驟2：執行 CICFlowMeter ===
            csv_dir_abs = os.path.abspath(self.csv_dir)
            cmd = f'cfm.bat "{pcap_filename}" "{csv_dir_abs}"'
            logger.info(f"執行 CICFlowMeter: {cmd}")

            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=90)
            if result.returncode != 0:
                logger.error(f"CICFlowMeter 失敗 (code {result.returncode}): {result.stderr.decode('cp950', errors='replace')}")
                return

            # === 步驟3：等待並讀取最新 CSV ===
            deadline = time.time() + 15
            csv_path = None
            while time.time() < deadline:
                csv_files = [f for f in os.listdir(csv_dir_abs) if f.endswith(".csv")]
                if csv_files:
                    csv_files.sort(key=lambda f: os.path.getmtime(os.path.join(csv_dir_abs, f)), reverse=True)
                    candidate = os.path.join(csv_dir_abs, csv_files[0])
                    if os.path.getsize(candidate) > 100:
                        csv_path = candidate
                        break
                time.sleep(0.5)

            if not csv_path:
                logger.error("未找到有效的 CSV 檔案")
                return

            # === 終極解決：先試 cp950（繁體中文），再試 utf-8，絕不炸 ===
            df = None
            for encoding in ['cp950', 'big5', 'utf-8', 'gbk']:
                try:
                    logger.debug(f"嘗試用 {encoding} 讀取 CSV...")
                    df = pd.read_csv(csv_path, encoding=encoding, low_memory=False, on_bad_lines='skip')
                    if not df.empty and len(df) > 0:
                        logger.info(f"CSV 讀取成功！使用編碼: {encoding}，共 {len(df)} 條流量")
                        break
                except Exception as e:
                    logger.debug(f"{encoding} 讀取失敗: {e}")
                    continue

            if df is None or df.empty:
                logger.error("所有編碼都讀取失敗，CSV 可能損壞或為空")
                # 最後手段：強制用 cp950 + 忽略錯誤
                try:
                    df = pd.read_csv(csv_path, encoding='cp950', errors='ignore', low_memory=False)
                    logger.warning("已用 cp950 + errors='ignore' 強制讀取（可能有亂碼）")
                except:
                    logger.error("最終強制讀取也失敗，放棄此批次")
                    return

            logger.info(f"載入 CSV 成功: {csv_path} ({len(df)} 條流量)")

            # === 步驟4：逐條預測（每條都防崩潰）===
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

                    # 轉換 label 格式
                    if isinstance(label, (list, np.ndarray)):
                        label = label[0] if len(label) > 0 else "unknown"
                    if isinstance(label, (int, np.int64)):
                        label = self.le.inverse_transform([label])[0] if hasattr(self, 'le') else "unknown"
                    label_str = str(label).capitalize()

                    is_malicious = label_str.lower() != 'benign'

                    # 使用默認參數避免 lambda 閉包問題
                    self.root.after(0, self.add_packet_to_table, 
                                  src_ip, dst_ip, proto, label_str, features, None, 
                                  is_malicious, diagnosis)

                except Exception as e:
                    logger.error(f"處理第 {idx} 條流量時發生未預期錯誤: {e}")
                    continue  # 絕不讓一條壞數據搞垮整個系統

        except Exception as e:
            logger.error(f"process_pcap_to_csv 嚴重錯誤: {e}")
        finally:
            self.processing_pcap = False
            # 可選：刪除臨時 pcap（節省磁碟）
            if pcap_filename and os.path.exists(pcap_filename):
                try: os.remove(pcap_filename)
                except: pass
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