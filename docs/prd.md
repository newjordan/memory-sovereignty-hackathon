# PRD — Memory Sovereignty Module (Rust Core + OpenClaw Skill)

## 1. Overview
### Problem
Persistent memory is both a superpower and a vulnerability. File-backed memory can be:
- accidentally overwritten,
- subtly poisoned by untrusted content,
- modified post-hoc in a way that creates false continuity.

### Goal
Provide a local-first system that:
- makes memory writes explicit and governed,
- records provenance,
- produces verifiable receipts and daily checkpoints,
- keeps memory contents private via encryption,
- imposes **no ongoing cost** on the operator by default.

### Target track
USDC Hackathon — **Best OpenClaw Skill**.

## 2. User stories
### Primary
- As an agent, I can append a memory entry and receive a signed receipt.
- As an agent/human, I can verify a receipt later and detect tampering.
- As an agent, I can ask: “Do I have an X on YYYY-MM-DD?” and verify the daily checkpoint.
- As an operator, I can enforce “write-protected by default” with explicit allow rules.

### Secondary
- As an agent, I can quarantine “untrusted” notes and only promote them with explicit human confirmation.
- As an operator, I can rotate keys and maintain continuity proofs across rotations.

## 3. Functional requirements
### FR-1 Initialization
- Generate per-agent identity:
  - Ed25519 keypair for signing receipts.
  - Symmetric encryption key for content.
- Persist keys locally with safe permissions.

### FR-2 Append entry
- Input: plaintext content + provenance metadata.
- Encrypt content.
- Create append-only entry with:
  - index
  - created_at
  - provenance
  - ciphertext
  - prev_entry_hash
  - entry_hash
- Return **receipt** containing:
  - agent public key
  - entry_hash
  - index
  - created_at
  - signature

### FR-3 Daily checkpoint
- Generate a daily checkpoint receipt:
  - derived from last entry hash (or Merkle root of day entries).
- Allow verification that a day exists in the chain.

### FR-4 Verification
- Verify receipt signature.
- Verify hash chain integrity up to a given index.
- Verify daily checkpoint against the local log.

### FR-5 Policy enforcement (memory sovereignty)
- Default: deny writes except through the module/skill.
- Provide rules:
  - allow write for certain sources/kinds
  - require human-confirmation flag for promotion to long-term
  - optional TTL for unverified entries

### FR-6 OpenClaw skill interface
Expose safe commands:
- `memory.init()`
- `memory.append(content, provenance)`
- `memory.checkpoint(day)`
- `memory.verify(receipt_or_day)`
- `memory.export(day|range)`

## 4. Non-functional requirements
- **Security**: no secrets printed to stdout by default; safe file permissions.
- **Privacy**: ciphertext only; provenance is minimal and configurable.
- **Portability**: Linux first; no heavyweight deps.
- **Usability**: single-command demo script.
- **Cost**: no onchain writes by default; no cloud services required.

## 5. Out of scope (v1)
- Public commons anchoring / onchain attestations (optional future plugin only).
- Multi-agent witness signatures.
- Full GUI.

## 6. Acceptance criteria
- Editing any prior entry causes verification failure.
- Receipts cannot be forged without signing key (demonstrated by negative tests).
- Daily checkpoint exists and is verifiable.
- Another agent can run the demo from README.

## 7. Risks
- Key compromise: if private key is stolen, an attacker can forge receipts.
  - Mitigation: document storage, recommend hardware key stores where available, support rotation.
- Timestamp trust: local timestamps can be manipulated.
  - Mitigation: chain index ordering is still strict; optional future anchors.
