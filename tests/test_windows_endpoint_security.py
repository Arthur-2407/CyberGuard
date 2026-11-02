"""tests/test_windows_endpoint_security.py

Automated Test Suite for CyberGuard Windows Desktop Security Architecture:
  1. Real-Time File Monitoring & Static Inspection (Shannon entropy, EICAR, double extension)
  2. Quarantine Vault Lifecycle (Atomic isolation, .cgq XOR obfuscation, safe rollback, shred)
  3. Process & Application Execution Monitor (LOLBin rules, temp folder execution flags)
  4. Live Web & DNS Shield (Malicious domain blocking, punycode lookalikes, allowlists)
  5. Gmail Protection & Official Admin Whitelist (cyberguardadmin@gmail.com bypass)
  6. Multi-Tenant User Isolation & Local Store Persistence
  7. Dual Edition Distribution Parity (Standard Installer & Portable packaging targets)
"""

import json
import subprocess
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
DESKTOP_DIR = ROOT_DIR / "desktop"


def test_01_local_store_user_tenant_isolation(tmp_path):
    """
    Verify that LocalStore strictly isolates alerts, history, and scans by user_id.
    User A cannot view User B's alerts.
    """
    node_script = f"""
    const path = require('path');
    const localStore = require('{DESKTOP_DIR.as_posix()}/engine/local_store.js');

    // Add alert for User 101
    localStore.addAlert({{
        title: 'User 101 Threat',
        details: 'Malware drop in downloads',
        user_id: 101
    }});

    // Add alert for User 202
    localStore.addAlert({{
        title: 'User 202 Phishing',
        details: 'Phishing email clicked',
        user_id: 202
    }});

    const u101Alerts = localStore.getAlerts(101);
    const u202Alerts = localStore.getAlerts(202);

    const hasLeakage = u101Alerts.some(a => a.user_id === 202) || u202Alerts.some(a => a.user_id === 101);

    console.log(JSON.stringify({{
        u101Count: u101Alerts.length,
        u202Count: u202Alerts.length,
        hasLeakage: hasLeakage
    }}));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)
    assert data["u101Count"] >= 1
    assert data["u202Count"] >= 1
    assert not data["hasLeakage"], "Cross-user data leakage detected in LocalStore alerts!"


def test_02_file_watcher_static_inspection_and_eicar(tmp_path):
    """
    Verify FileWatcher static analyzer accurately computes Shannon entropy,
    detects the EICAR test string as MALICIOUS, and flags double extension masking.
    """
    eicar_file = tmp_path / "test_eicar.com"
    eicar_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", encoding="ascii")

    double_ext = tmp_path / "invoice.pdf.exe"
    double_ext.write_bytes(b"MZ" + b"\x00" * 200)

    clean_file = tmp_path / "document.txt"
    clean_file.write_text("This is a benign corporate policy document.", encoding="utf-8")

    node_script = f"""
    const path = require('path');
    const fileWatcher = require('{DESKTOP_DIR.as_posix()}/engine/file_watcher.js');

    const eicarRes = fileWatcher.analyzeLocalFile('{eicar_file.as_posix()}');
    const doubleRes = fileWatcher.analyzeLocalFile('{double_ext.as_posix()}');
    const cleanRes = fileWatcher.analyzeLocalFile('{clean_file.as_posix()}');

    console.log(JSON.stringify({{
        eicar: eicarRes,
        doubleExt: doubleRes,
        clean: cleanRes
    }}));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)

    assert data["eicar"]["verdict"] == "MALICIOUS"
    assert "EICAR" in data["eicar"]["threatName"]

    assert data["doubleExt"]["verdict"] == "SUSPICIOUS"
    assert "DoubleExtension" in data["doubleExt"]["threatName"]

    assert data["clean"]["verdict"] == "CLEAN"
    assert data["clean"]["threatName"] is None


def test_03_quarantine_vault_atomic_isolation_and_rollback(tmp_path):
    """
    Verify QuarantineManager atomically isolates a file, obfuscates bytes (.cgq),
    records SHA-256 metadata, and can restore the file with 100% byte integrity.
    """
    payload_file = tmp_path / "suspicious_payload.bin"
    original_bytes = b"CYBERGUARD_TEST_MALWARE_PAYLOAD_BINARY_CONTENT_1234567890"
    payload_file.write_bytes(original_bytes)

    node_script = f"""
    const path = require('path');
    const fs = require('fs');
    const quarantine = require('{DESKTOP_DIR.as_posix()}/engine/quarantine_manager.js');

    const filePath = '{payload_file.as_posix()}';
    const entry = quarantine.quarantineFile(filePath, {{
        threatName: 'Test.Trojan.Mock',
        category: 'MALWARE',
        severity: 'HIGH'
    }}, 42);

    const existsOriginalAfterQuarantine = fs.existsSync(filePath);
    const vaultFile = path.join(quarantine.quarantineDir, entry.id + '.cgq');
    const vaultExists = fs.existsSync(vaultFile);

    // Verify vault file is NOT plain original bytes (obfuscated)
    const vaultBytes = fs.readFileSync(vaultFile);
    const isObfuscated = !vaultBytes.equals(Buffer.from('{original_bytes.decode()}'));

    // Restore file
    const restoreRes = quarantine.restoreFile(entry.id, filePath, 42);
    const existsOriginalAfterRestore = fs.existsSync(filePath);
    const restoredBytes = fs.readFileSync(filePath);
    const byteIntegrity = restoredBytes.equals(Buffer.from('{original_bytes.decode()}'));

    console.log(JSON.stringify({{
        quarantineId: entry.id,
        existsOriginalAfterQuarantine,
        vaultExists,
        isObfuscated,
        existsOriginalAfterRestore,
        byteIntegrity
    }}));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)

    assert not data["existsOriginalAfterQuarantine"], "Original file should be moved during quarantine!"
    assert data["vaultExists"], "Vault file (.cgq) should exist in quarantine vault!"
    assert data["isObfuscated"], "Quarantined file must be byte-obfuscated to prevent accidental execution!"
    assert data["existsOriginalAfterRestore"], "Restored file must reappear at destination!"
    assert data["byteIntegrity"], "Restored file must match original bytes exactly!"


def test_04_web_shield_rules_and_punycode_detection():
    """
    Verify WebShield evaluates known malicious domains, detects punycode homographs,
    and enforces localhost/infrastructure allowlist.
    """
    node_script = f"""
    const webShield = require('{DESKTOP_DIR.as_posix()}/engine/web_shield.js');

    const r1 = webShield.evaluateUrl('https://testsafebrowsing.appspot.com/test');
    const r2 = webShield.evaluateUrl('https://xn--pple-43d.com/login'); // Punycode lookalike
    const r3 = webShield.evaluateUrl('http://127.0.0.1:3000/api/health');
    const r4 = webShield.evaluateUrl('https://legitimate-corp.com/home');

    console.log(JSON.stringify({{
        malicious: r1,
        punycode: r2,
        allowlist: r3,
        clean: r4
    }}));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)

    assert data["malicious"]["verdict"] == "BLOCKED"
    assert data["punycode"]["verdict"] == "SUSPICIOUS"
    assert data["punycode"]["threat"] == "PUNYCODE_HOMOGRAPH"
    assert data["allowlist"]["verdict"] == "ALLOWED"
    assert data["clean"]["verdict"] == "ALLOWED"


def test_05_gmail_protection_cyberguard_admin_exemption():
    """
    Verify GmailSecurityService evaluates phishing patterns and strictly
    exempts official CyberGuard administrative emails (cyberguardadmin@gmail.com).
    """
    node_script = f"""
    const gmailService = require('{DESKTOP_DIR.as_posix()}/engine/gmail_service.js');

    // 1. Benign CyberGuard Admin Email (must be exempted)
    const adminMsg = {{
        from: 'CyberGuard Security <cyberguardadmin@gmail.com>',
        replyTo: 'cyberguardadmin@gmail.com',
        authenticationResults: 'spf=pass dkim=pass dmarc=pass',
        subject: 'CyberGuard Urgent Security Notification',
        body: 'Please verify your account immediately at https://cyberguard.local'
    }};
    const adminRes = gmailService.inspectEmail(adminMsg, 1);

    // 2. Malicious Phishing Email (must be flagged)
    const phishingMsg = {{
        from: 'Bank Alert <support@fake-bank-auth.xyz>',
        replyTo: 'harvester@evil-stealer.ru',
        subject: 'Urgent: Your account will be suspended in 24 hours',
        body: 'Verify your account immediately or access will be permanently terminated.',
        attachments: [{{ filename: 'invoice_details.pdf.exe', size: 1048576 }}]
    }};
    const phishingRes = gmailService.inspectEmail(phishingMsg, 1);

    console.log(JSON.stringify({{
        admin: adminRes,
        phishing: phishingRes
    }}));
    """

    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    data = json.loads(res.stdout)

    # Official CyberGuard admin exemption check
    assert data["admin"]["verdict"] == "CLEAN", "CyberGuard admin email should be exempted from phishing flags!"
    assert data["admin"]["isTrustedAdmin"] is True

    # Phishing detection check
    assert data["phishing"]["verdict"] in ["PHISHING_THREAT", "SUSPICIOUS"]
    assert data["phishing"]["riskScore"] >= 0.5
    assert len(data["phishing"]["indicators"]) >= 2


def test_06_package_json_dual_edition_distribution():
    """
    Verify desktop/package.json configures both NSIS installer and Portable edition targets.
    """
    pkg_file = DESKTOP_DIR / "package.json"
    pkg = json.loads(pkg_file.read_text(encoding="utf-8"))

    win_targets = [t["target"] for t in pkg["build"]["win"]["target"]]
    assert "nsis" in win_targets, "NSIS installer target missing in desktop/package.json!"
    assert "portable" in win_targets, "Portable edition target missing in desktop/package.json!"
    assert "portable" in pkg["build"], "Portable build options missing in desktop/package.json!"
    assert pkg["build"]["portable"]["artifactName"] == "CyberGuard-Portable.${ext}"
