# ⚡ Pure P2P Genesis AI

**100% 탈중앙화 분산 학습 네트워크** - 브라우저에서 직접 AI를 학습하고 P2P로 공유하세요!

## 🌟 핵심 특징

### 🚫 중앙 서버 Zero
- ✅ **No Backend** - Python/Node 서버 불필요
- ✅ **No Database** - 모든 데이터 localStorage + P2P
- ✅ **No Cloud Costs** - Firebase Hosting만 사용 (무료)

### 🧠 브라우저 AI 학습
- TensorFlow.js로 실시간 학습
- Wikipedia 데이터로 자동 훈련
- 모델 파라미터 자동 저장/로딩

### 🌐 P2P 네트워크
- PeerJS (WebRTC) 기반 직접 연결
- Gossip Protocol로 네트워크 확장
- 더 나은 모델만 수락하는 Consensus

### ⛓️ P2P 블록체인
- 학습 기록을 블록체인에 기록
- 블록 마이닝 시 10 GEN 보상
- localStorage로 영구 저장

### 🔐 완전 영속성
- **Wallet Address** - 영구 고정
- **Peer ID** - 재접속 시 동일
- **Balance** - 브라우저에 저장
- **Blockchain** - 로컬 + P2P 동기화

## 🚀 사용 방법

### 1. 웹사이트 접속
```
https://mindnet-ai.web.app
```

### 2. 학습 시작
1. "START DISTRIBUTED LEARNING" 클릭
2. 자동으로 Wikipedia에서 데이터 수집
3. 브라우저에서 AI 학습 시작
4. Loss 개선 시 블록 마이닝 + 보상 획득

### 3. 네트워크 참여
1. "COPY INVITE LINK" 클릭
2. 친구에게 링크 공유
3. 자동으로 P2P 연결
4. 더 나은 AI 모델 자동 동기화

## 🏗️ 기술 스택

```
Frontend Only Architecture:

┌─────────────────────────────────────┐
│         Browser (index.html)         │
├─────────────────────────────────────┤
│ TensorFlow.js  │  AI 학습 + 추론    │
│ PeerJS/WebRTC  │  P2P 통신          │
│ localStorage   │  데이터 영속화      │
│ Chart.js       │  시각화            │
│ Elliptic.js    │  암호화 (지갑)      │
└─────────────────────────────────────┘
         │              │
         ▼              ▼
   Wikipedia API    P2P Peers
```

## 📊 데이터 흐름

```
학습 데이터
   │
   ├─► Wikipedia API → 브라우저
   │
   ├─► TensorFlow.js 학습
   │
   ├─► Loss 개선? 
   │      ├─ YES → 블록체인에 기록
   │      │         └─► P2P 브로드캐스트
   │      │                └─► 다른 노드들이 수신/검증
   │      │
   │      └─ NO  → 다음 Epoch
   │
   └─► localStorage 저장
```

## 🎮 UI 구성

- **P2P Network** - 연결된 피어, 네트워크 노드 수
- **Mining Control** - 학습 시작/중지
- **Local Stats** - Epochs, Loss, 블록체인 높이
- **Neural Evolution** - Loss 그래프
- **Currently Learning** - 현재 학습 중인 Wikipedia 주제
- **P2P Activity Log** - 실시간 네트워크 활동
- **Test Local AI** - 학습된 AI로 텍스트 생성

## 💰 토크노믹스

- **마이닝 보상**: 블록당 10 GEN
- **블록 생성 조건**: 이전보다 낮은 Loss 달성
- **발란스 저장**: localStorage (영구)
- **미래 기능**: P2P 거래, AI 질의 수수료

## 🔧 로컬 실행

```bash
# 1. 클론
git clone https://github.com/astroidground/mindnet-ai.git
cd mindnet-ai

# 2. 브라우저로 열기
open index.html
# 또는
python -m http.server 8000
# http://localhost:8000 접속
```

## 📁 프로젝트 구조

```
mindnet-ai/
├── index.html          # 메인 애플리케이션 (Pure P2P)
├── firebase.json       # Firebase Hosting 설정
├── README.md           # 이 파일
└── archive/            # 레거시 파일 (중앙 서버 시절)
    ├── genesis_dna.py  # 구 Python 서버
    ├── index_p2p.html  # P2P 전환 초기 버전
    └── ...
```

## 🌍 배포

### Firebase Hosting (현재)
```bash
firebase deploy --only hosting
```

### 또는 어디든지!
- GitHub Pages
- Netlify
- Vercel
- 심지어 로컬 파일로도 실행 가능!

## 🔮 로드맵

- [x] Pure P2P 네트워크
- [x] P2P 블록체인
- [x] 마이닝 보상 시스템
- [x] Peer ID 영속성
- [ ] P2P 거래 시스템
- [ ] 고급 AI 모델 (Transformer)
- [ ] 모바일 지원 (PWA)
- [ ] IPFS 통합

## ⚠️ 알려진 제약

- **PeerJS 서버**: 무료 public 서버 사용 (혼잡 가능)
- **브라우저 저장**: localStorage 용량 제한 (~10MB)
- **학습 속도**: GPU 없이 CPU/WebGL만 사용
- **네트워크 발견**: URL 공유 기반 (DHT 미구현)

## 🤝 기여

Pull Request는 언제나 환영합니다!

## 📄 라이선스

MIT License - 자유롭게 사용, 수정, 배포하세요!

## 🙏 감사

- TensorFlow.js Team
- PeerJS Project
- Wikipedia API
- Firebase Hosting

---

**Made with 🧠 by Pure P2P Genesis AI Community**

🌐 **Live Demo**: https://mindnet-ai.web.app

