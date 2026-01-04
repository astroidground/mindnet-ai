import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import time
import json
import os
import random
import secrets
import base64
from typing import Any

# 필수 라이브러리 체크
try:
    import requests
    from bs4 import BeautifulSoup
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
except ImportError:
    print("CRITICAL: pip install requests beautifulsoup4 flask flask-cors cryptography")
    exit(1)

# --- Configuration ---
DB_FILE = "genesis_ledger.db"
KEY_FILE = "genesis_wallet.pem"
VERSION = "0.1.1-Evolution"
EVOLUTION_INTERVAL = 100 # 100블록마다 뇌 구조 진화

def calculate_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

def get_timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S')

class Wallet:
    def __init__(self, key_file: str = KEY_FILE):
        self.key_file = key_file
        self.private_key = self._load_or_generate_key()
        self.public_key = self.private_key.public_key()
        self.address = self.get_address()

    def _load_or_generate_key(self):
        if os.path.exists(self.key_file):
            print(f"🔐 Loading wallet from {self.key_file}")
            with open(self.key_file, "rb") as key_file:
                return serialization.load_pem_private_key(key_file.read(), password=None)
        else:
            print("🆕 Generating new SECP256K1 wallet...")
            private_key = ec.generate_private_key(ec.SECP256K1())
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self.key_file, "wb") as f:
                f.write(pem)
            return private_key

    def get_address(self) -> str:
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_hash = hashlib.sha256(pub_bytes).hexdigest()
        return f"GEN_{pub_hash[:20]}"

    # [업데이트] 서명 검증 로직 활성화 및 JS 호환성 개선
    @staticmethod
    def verify_signature(public_key_hex: str, message: str, signature_obj: dict) -> bool:
        try:
            # JS에서 온 Hex Public Key를 SECP256K1 포인트로 변환
            curve = ec.SECP256K1()
            if not public_key_hex.startswith('04'):
                public_key_hex = '04' + public_key_hex
            pub_key_bytes = bytes.fromhex(public_key_hex)
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, pub_key_bytes)
            
            # JS의 r, s 값을 DER 포맷으로 인코딩
            r = int(signature_obj['r'], 16)
            s = int(signature_obj['s'], 16)
            signature = encode_dss_signature(r, s)

            public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            print(f"⚠️ Verification Failed: {e}")
            return False

class Ledger:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # [업데이트] 가중치(뇌 데이터)를 저장할 테이블 구조 최적화
        cursor.execute('''CREATE TABLE IF NOT EXISTS balances (
            address TEXT PRIMARY KEY, 
            balance REAL DEFAULT 0.0, 
            pk_hex TEXT
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS chain (
            idx INTEGER PRIMARY KEY AUTOINCREMENT, 
            timestamp TEXT, 
            prev_hash TEXT, 
            data_hash TEXT, 
            weights_hash TEXT, 
            miner TEXT, 
            loss REAL, 
            block_hash TEXT
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS brain_state (
            generation INTEGER PRIMARY KEY, 
            weights_json TEXT, 
            last_loss REAL, 
            timestamp TEXT
        )''')
        
        conn.commit()
        
        # Genesis Block
        cursor.execute('SELECT count(*) FROM chain')
        if cursor.fetchone()[0] == 0:
            print("⚡ Minting Genesis Block...")
            cursor.execute('''INSERT INTO chain (timestamp, prev_hash, data_hash, weights_hash, miner, loss, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                (get_timestamp(), "0"*64, "GENESIS", "GENESIS", "SYSTEM", 0.0, "GENESIS_HASH"))
            conn.commit()
        
        # Genesis Brain State 설정
        cursor.execute('SELECT count(*) FROM brain_state')
        if cursor.fetchone()[0] == 0:
            cursor.execute('INSERT INTO brain_state VALUES (1, "[]", 9.9, ?)', (get_timestamp(),))
            conn.commit()
        
        conn.close()

    def get_last_block(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM chain ORDER BY idx DESC LIMIT 1')
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_balance(self, address: str) -> float:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM balances WHERE address = ?", (address,))
        res = cursor.fetchone()
        conn.close()
        return res[0] if res else 0.0

    def update_balance(self, address: str, amount: float, pk_hex: str = None) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO balances (address, balance, pk_hex) 
                VALUES (?, ?, ?) 
                ON CONFLICT(address) 
                DO UPDATE SET balance = balance + ?, pk_hex = COALESCE(pk_hex, ?)
            ''', (address, amount, pk_hex, amount, pk_hex))
            conn.commit()
            return True
        except Exception as e:
            print(f"DB Error: {e}")
            return False
        finally:
            conn.close()

    def append_block(self, miner: str, data_hash: str, weights_hash: str, metadata: dict):
        last_block = self.get_last_block()
        new_block = {
            "idx": last_block['idx'] + 1,
            "timestamp": get_timestamp(),
            "prev_hash": last_block['block_hash'],
            "data_hash": data_hash,
            "weights_hash": weights_hash,
            "miner": miner,
            "loss": metadata.get('loss', 0.0)
        }
        block_hash = calculate_hash(new_block)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO chain (timestamp, prev_hash, data_hash, weights_hash, miner, loss, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (new_block['timestamp'], new_block['prev_hash'], data_hash, weights_hash, miner, new_block['loss'], block_hash))
        conn.commit()
        conn.close()
        print(f"🧱 Block #{new_block['idx']} mined by {miner[:10]}")
        return new_block

    def save_evolution(self, generation, weights_json, loss):
        """더 낮은 Loss(더 똑똑한 뇌)가 들어오면 업데이트"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO brain_state (generation, weights_json, last_loss, timestamp) 
                          VALUES (?, ?, ?, ?) ON CONFLICT(generation) 
                          DO UPDATE SET weights_json = excluded.weights_json, last_loss = excluded.last_loss, timestamp = excluded.timestamp
                          WHERE excluded.last_loss < brain_state.last_loss''', 
                       (generation, json.dumps(weights_json), loss, get_timestamp()))
        
        if cursor.rowcount > 0:
            print(f"🧠 [Evolution] Gen {generation} brain upgraded (Loss: {loss:.4f})")
        
        conn.commit()
        conn.close()

    def get_current_brain(self, generation):
        """현재 세대의 최고 뇌 상태 반환"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT weights_json FROM brain_state WHERE generation = ?", (generation,))
        res = cursor.fetchone()
        conn.close()
        return json.loads(res[0]) if res else []

# --- Layer 2: Crawler (Lightweight) ---
class Crawler:
    def forage(self) -> str:
        # Simple Wikipedia Scraper
        topics = ["Artificial_intelligence", "Evolution", "Blockchain", "Neural_network", "Genetic_algorithm", "Life", "Universe", "Philosophy", "Mathematics"]
        try:
            topic = random.choice(topics)
            url = f"https://en.wikipedia.org/wiki/{topic}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            res = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            paragraphs = soup.find_all('p')
            text_content = ""
            for p in paragraphs:
                if len(p.text) > 100:
                    text_content += p.text + " "
                if len(text_content) > 1000:
                    break
            
            if not text_content or len(text_content) < 50:
                return "Genesis AI is evolving. Searching for knowledge in the digital void... " * 10
                
            return text_content[:1000]
        except Exception as e:
            print(f"Crawler Error: {e}")
            return "Genesis AI is evolving. Searching for knowledge in the digital void... " * 10

# --- Main Server Node ---
class MindHashNode:
    def __init__(self, port: int = 5000):
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.ledger = Ledger()
        self.wallet = Wallet()
        self.crawler = Crawler()
        
        self.current_job = None
        self.last_job_time = 0
        
        # [업데이트] 활성 노드 추적
        self.active_nodes = {}  # {address: last_seen_timestamp}
        self.node_timeout = 30  # 30초 동안 활동 없으면 offline
        
        self.setup_routes()
        
        print(f"🌌 MindHash Evolution Node (v{VERSION}) Initialized")
        print(f"🔑 Server Wallet: {self.wallet.address}")

    def update_node_activity(self, address: str):
        """노드의 마지막 활동 시간 기록"""
        self.active_nodes[address] = time.time()
    
    def get_active_node_count(self) -> int:
        """활성 노드 수 반환 (타임아웃 제외)"""
        current_time = time.time()
        active = [addr for addr, last_seen in self.active_nodes.items() 
                  if current_time - last_seen < self.node_timeout]
        # 비활성 노드 정리
        self.active_nodes = {addr: ts for addr, ts in self.active_nodes.items() if addr in active}
        return len(active)

    def setup_routes(self):
        
        @self.app.route('/', methods=['GET'])
        def home():
            last_block = self.ledger.get_last_block()
            return jsonify({
                "name": "Genesis MindHash Node",
                "version": VERSION,
                "status": "online",
                "height": last_block['idx'] if last_block else 0
            })

        @self.app.route('/balance/<address>', methods=['GET'])
        def balance(address):
            return jsonify({"address": address, "balance": self.ledger.get_balance(address)})
        
        @self.app.route('/stats', methods=['GET'])
        def stats():
            """[업데이트] 네트워크 통계 (활성 노드 수 등)"""
            last_block = self.ledger.get_last_block()
            return jsonify({
                "active_nodes": self.get_active_node_count(),
                "total_blocks": last_block['idx'] if last_block else 0,
                "version": VERSION
            })

        @self.app.route('/mining/job', methods=['GET'])
        def get_job():
            """[업데이트] 유저에게 현재의 '뇌 상태(Weights)'를 함께 전달하여 이어서 학습하게 함"""
            # [업데이트] 노드 활동 기록
            address = request.args.get('address')
            if address:
                self.update_node_activity(address)
            
            if not self.current_job or time.time() - self.last_job_time > 30:
                last_block = self.ledger.get_last_block()
                idx = last_block['idx'] if last_block else 0
                generation = 1 + (idx // EVOLUTION_INTERVAL)
                
                self.current_job = {
                    "job_id": secrets.token_hex(4),
                    "data": self.crawler.forage(),
                    "epoch": idx,
                    "generation": generation,
                    "current_weights": self.ledger.get_current_brain(generation) # 지능 계승
                }
                self.last_job_time = time.time()
                print(f"📤 [Job] Gen {generation} Job {self.current_job['job_id']} dispatched")

            return jsonify(self.current_job)

        @self.app.route('/mining/submit', methods=['POST'])
        def submit_work():
            """[업데이트] 보안 검증 강화 및 가중치 저장"""
            try:
                data = request.json
                
                # [업데이트] 노드 활동 기록
                if 'address' in data:
                    self.update_node_activity(data['address'])
                
                # Construct verification message
                msg = f"JOB:{data['job_id']}:LOSS:{float(data['loss']):.4f}"
                
                # Parse signature object
                sig_obj = data['signature'] if isinstance(data['signature'], dict) else json.loads(data['signature'])
                
                # [업데이트] 실제 서명 검증
                if not Wallet.verify_signature(data['public_key'], msg, sig_obj):
                    return jsonify({"error": "Invalid Cryptographic Proof"}), 401

                loss = float(data['loss'])
                
                # Loss threshold check
                if loss > 5.0:
                    return jsonify({"status": "rejected", "reason": "loss_too_high"}), 400

                # [업데이트] 가중치(뇌세포) 저장 - 진짜 학습이 일어남
                self.ledger.save_evolution(
                    data['generation'], 
                    data['weights'], # 브라우저가 보낸 Float32Array 가중치
                    loss
                )

                # 블록체인 기록
                weights_hash = hashlib.sha256(json.dumps(data['weights']).encode()).hexdigest()
                self.ledger.append_block(
                    miner=data['address'],
                    data_hash=hashlib.sha256(self.current_job['data'].encode()).hexdigest(),
                    weights_hash=weights_hash,
                    metadata={"loss": loss, "job_id": data['job_id']}
                )
                
                # 보상 지급
                reward = 1.0
                self.ledger.update_balance(data['address'], reward, data['public_key'])
                
                return jsonify({
                    "status": "accepted",
                    "reward": reward,
                    "new_balance": self.ledger.get_balance(data['address'])
                })

            except Exception as e:
                print(f"Submit Error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/ask_network', methods=['POST'])
        def ask_network():
            """질문 중계 (경량 서버는 직접 추론 안함)"""
            data = request.json
            question = data.get('question')
            address = data.get('address')
            
            fee = 1.0
            if self.ledger.get_balance(address) < fee:
                return jsonify({"error": "Insufficient GEN"}), 402
            
            self.ledger.update_balance(address, -fee)
            
            return jsonify({
                "results": [
                    {"node": "Genesis Oracle", "answer": "Collective wisdom is being aggregated..."}
                ],
                "new_balance": self.ledger.get_balance(address)
            })

    def run(self):
        port = int(os.environ.get("PORT", self.port))
        self.app.run(host='0.0.0.0', port=port)

if __name__ == "__main__":
    node = MindHashNode()
    node.run()
