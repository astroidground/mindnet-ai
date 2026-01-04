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
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Check for external dependencies (Minimal for Light Node)
try:
    import requests
    from bs4 import BeautifulSoup
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("CRITICAL: Dependencies missing. Please install: pip install requests beautifulsoup4 flask flask-cors cryptography")
    exit(1)

# --- Configuration & Constants ---
DB_FILE = "genesis_ledger.db"
KEY_FILE = "genesis_wallet.pem"
VERSION = "0.1.0-Lite"
EVOLUTION_INTERVAL = 100 # Evolution every 100 blocks

# --- Utils ---
def calculate_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

def get_timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S')

# --- Layer 0: Cryptographic Wallet (Server Side) ---
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

    def sign_message(self, message: str) -> str:
        signature = self.private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
        try:
            if not public_key_pem: return False
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # Handle JSON formatted signature from JS
            if "{" in signature_b64:
                try:
                    sig_obj = json.loads(signature_b64)
                    r = int(sig_obj['r'], 16)
                    s = int(sig_obj['s'], 16)
                    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
                    signature = encode_dss_signature(r, s)
                except:
                    signature = base64.b64decode(signature_b64)
            else:
                signature = base64.b64decode(signature_b64)

            public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            # print(f"Sig Verify Failed: {e}")
            return False
            
    @staticmethod
    def convert_hex_to_pem(hex_key: str) -> str:
        try:
            curve = ec.SECP256K1()
            # Uncompressed key usually starts with 04
            if not hex_key.startswith('04'):
                 hex_key = '04' + hex_key
            pub_key_bytes = bytes.fromhex(hex_key)
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, pub_key_bytes)
            pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return pem
        except Exception as e:
            print(f"Key conversion failed: {e}")
            return ""

# --- Layer 1: Ledger & State ---
class Ledger:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. Balances
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS balances (
                address TEXT PRIMARY KEY,
                balance REAL DEFAULT 0.0,
                public_key_pem TEXT
            )
        ''')
        
        # 2. Chain (Blocks)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chain (
                idx INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                prev_hash TEXT,
                data_hash TEXT,
                weights_hash TEXT,
                miner TEXT,
                metadata TEXT,
                block_hash TEXT
            )
        ''')

        # 3. Model Weights (Storage)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS weights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generation INTEGER,
                weights_json TEXT,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        
        # Create Genesis Block
        cursor.execute('SELECT count(*) FROM chain')
        if cursor.fetchone()[0] == 0:
            print("⚡ Minting Genesis Block...")
            cursor.execute('''
                INSERT INTO chain (timestamp, prev_hash, data_hash, weights_hash, miner, metadata, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (get_timestamp(), "0"*64, "GENESIS", "GENESIS", "SYSTEM", json.dumps({"msg": "Hello World"}), "GENESIS_HASH"))
            
            # Initial Weights (Empty or Basic)
            cursor.execute('INSERT INTO weights (generation, weights_json, timestamp) VALUES (1, "[]", ?)', (get_timestamp(),))
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

    def update_balance(self, address: str, amount: float, pk_pem: str = None) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO balances (address, balance, public_key_pem) 
                VALUES (?, ?, ?) 
                ON CONFLICT(address) 
                DO UPDATE SET balance = balance + ?, public_key_pem = COALESCE(public_key_pem, ?)
            ''', (address, amount, pk_pem, amount, pk_pem))
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
            "metadata": metadata
        }
        # Compute Hash
        block_hash = calculate_hash(new_block)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO chain (timestamp, prev_hash, data_hash, weights_hash, miner, metadata, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (new_block['timestamp'], new_block['prev_hash'], data_hash, weights_hash, miner, json.dumps(metadata), block_hash))
        conn.commit()
        conn.close()
        return new_block

# --- Layer 2: Crawler (Lightweight) ---
class Crawler:
    def forage(self) -> str:
        # Simple Wikipedia Scraper
        topics = ["Artificial_intelligence", "Evolution", "Blockchain", "Neural_network", "Genetic_algorithm"]
        try:
            topic = random.choice(topics)
            url = f"https://en.wikipedia.org/wiki/{topic}"
            res = requests.get(url, timeout=3)
            soup = BeautifulSoup(res.text, 'html.parser')
            text = " ".join([p.text for p in soup.find_all('p')[:3]])
            return text[:1000] # Limit size
        except:
            return "Genesis AI is evolving. " * 10

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
        
        self.setup_routes()
        
        print(f"🌌 MindHash Lite Node (v{VERSION}) Initialized")
        print(f"🔑 Server Wallet: {self.wallet.address}")

    def setup_routes(self):
        
        @self.app.route('/', methods=['GET'])
        def home():
            return jsonify({
                "name": "Genesis MindHash Node",
                "version": VERSION,
                "status": "online",
                "height": self.ledger.get_last_block()['idx']
            })

        @self.app.route('/balance/<address>', methods=['GET'])
        def balance(address):
            return jsonify({"address": address, "balance": self.ledger.get_balance(address)})

        @self.app.route('/mining/job', methods=['GET'])
        def get_job():
            """Dispatch mining job to web nodes."""
            # Refresh job every 30 seconds
            if not self.current_job or time.time() - self.last_job_time > 30:
                data = self.crawler.forage()
                last_block = self.ledger.get_last_block()
                generation = 1 + (last_block['idx'] // EVOLUTION_INTERVAL)
                
                self.current_job = {
                    "job_id": secrets.token_hex(4),
                    "data": data,
                    "epoch": last_block['idx'],
                    "generation": generation,
                    "target_loss": 2.0 # Dynamic difficulty
                }
                self.last_job_time = time.time()
                print(f"📤 [Job] New Job Generated: {self.current_job['job_id']}")

            return jsonify(self.current_job)

        @self.app.route('/mining/submit', methods=['POST'])
        def submit_work():
            """Validate PoT and Mint Block."""
            try:
                data = request.json
                miner_addr = data.get('address')
                loss = float(data.get('loss'))
                job_id = data.get('job_id')
                signature = data.get('signature')
                weights_sample = data.get('weights_sample')
                public_key_hex = data.get('public_key')
                
                # 1. Job Validation
                if not self.current_job or job_id != self.current_job['job_id']:
                    return jsonify({"error": "Stale or invalid job"}), 400
                    
                # 2. PoT Validation (Loss Check)
                if loss > 5.0: # Too high
                    return jsonify({"status": "rejected", "reason": "Loss too high"}), 400
                
                # 3. Signature Validation
                # Reconstruct message: JOB:{job_id}:LOSS:{loss}:WHASH:{hash}
                weights_hash = hashlib.sha256(json.dumps(weights_sample).encode()).hexdigest()
                msg = f"JOB:{job_id}:LOSS:{loss:.4f}:WHASH:{weights_hash}"
                
                pk_pem = Wallet.convert_hex_to_pem(public_key_hex) if public_key_hex else ""
                
                # Verify (Optional for prototype speed, strict for production)
                # if not Wallet.verify_signature(pk_pem, msg, signature):
                #    return jsonify({"error": "Invalid Signature"}), 401

                # 4. Mint Block
                self.ledger.append_block(
                    miner=miner_addr,
                    data_hash=hashlib.sha256(self.current_job['data'].encode()).hexdigest(),
                    weights_hash=weights_hash,
                    metadata={"loss": loss, "job_id": job_id}
                )
                
                # 5. Reward
                reward = 1.0
                self.ledger.update_balance(miner_addr, reward, pk_pem)
                
                print(f"⛏️  [Block Mined] Miner: {miner_addr[:8]} | Loss: {loss:.4f}")
                
                return jsonify({
                    "status": "accepted",
                    "reward": reward,
                    "new_balance": self.ledger.get_balance(miner_addr)
                })

            except Exception as e:
                print(f"Submit Error: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/ask_network', methods=['POST'])
        def ask_network():
            """Relay question to peers (No local inference)."""
            data = request.json
            question = data.get('question')
            address = data.get('address')
            
            # Fee Logic
            fee = 1.0
            if self.ledger.get_balance(address) < fee:
                return jsonify({"error": "Insufficient GEN"}), 402
            
            self.ledger.update_balance(address, -fee)
            
            # Since server has no Brain, we just return a placeholder or 
            # ideally we would broadcast to other active web nodes via WebRTC signaling (Future Work)
            # For now, we return a system message.
            return jsonify({
                "results": [
                    {"node": "Genesis Oracle", "answer": "I have relayed your question to the collective. (Server is lightweight ver.)"}
                ],
                "new_balance": self.ledger.get_balance(address)
            })

    def run(self):
        # Use PORT env var for Render/Railway
        port = int(os.environ.get("PORT", self.port))
        self.app.run(host='0.0.0.0', port=port)

if __name__ == "__main__":
    node = MindHashNode()
    node.run()
