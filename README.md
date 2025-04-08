<div align="center">

# 💎 Ultra Secure Messaging App 💎

**Next-Generation Secure Messaging.** <br/>
_Cryptography meets usability._

[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-green)](https://github.com/Hitesh-Jangid/SecureMessage) [![Release Version](https://img.shields.io/badge/Version-1.0.0-blueviolet)](https://github.com/Hitesh-Jangid/SecureMessage/releases) [![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen)](https://github.com/Hitesh-Jangid/SecureMessage/blob/main/CONTRIBUTING.md) </div>

---

**Ultra Secure Messaging App** redefines secure communication. It fuses robust, industry-standard cryptography (**AES + RSA Hybrid**) with **Digital Signatures** for absolute message integrity. Access it via a **powerful CLI** or a **sleek Qt GUI**, with **AI-driven Anomaly Detection** on the horizon. Open-source, private, and built for the modern era.

---

## ✨ Core Highlights ✨

| Feature                       | Description                                                                                              | Icon |
| :---------------------------- | :------------------------------------------------------------------------------------------------------- | :--: |
| **Bulletproof Encryption** | Hybrid **AES (256-bit CBC) + RSA (2048-bit OAEP)** ensures only you and your recipients can read messages. | 🔑   |
| **Verified Authenticity** | **RSA + SHA-256 Digital Signatures** on every message. No tampering, guaranteed sender identity.          | ✅   |
| **Dual Interfaces** | Choose between a rapid **CLI** or an intuitive, modern **Qt GUI** with a familiar chat layout.           | 💻🎨  |
| **Privacy First** | Minimal metadata handling and full user control over keys. Your conversations stay yours.                  | 🛡️   |
| **Multi-User Architecture** | Robust client/server model supports secure communication across different networks or locally.            | 👥   |
| **AI-Powered Security** | **[Coming Soon]** Real-time **Machine Learning** analysis to detect and alert on anomalous message patterns. | 🧠   |

---

## 🛠️ Tech Stack & Architecture

<details>
<summary><strong>🔩 Click to expand Architecture Details</strong></summary>

### Cryptography Core
* **Hybrid Encryption:** `AES-256-CBC` for content, `RSA-2048 (OAEP padding)` for AES key wrapping.
* **Digital Signatures:** `RSA-2048` with `SHA-256` hashing.
* **Key Management:** User-specific RSA keypairs (`.pem` files).
* **Secure Packet Format:** Hex-encoded serialized data: `(sender, recipients, [encrypted_AES_keys], iv, encrypted_payload, signature)`.

### Networking Layer
* **Server (`ServerApp`):** TCP listener, manages user registration (username + public key), routes encrypted packets.
* **Clients (`ClientApp`, `GUIApp`):** TCP connection to server, registration, sending/receiving secure packets via a shared networking module.

### User Interfaces
* **CLI (`ClientApp`):** Text-based interaction for sending/receiving messages.
* **GUI (`GUIApp`):** Qt5-based desktop application. Features multi-window chat, user prompts for setup, dedicated chat views per user (messages only appear for sender/recipient).

### Machine Learning Module (Future)
* **Anomaly Detection:** Planned Python module using `scikit-learn`/`joblib`. Analyzes decrypted message characteristics (size, frequency, content patterns) post-decryption.
* **Real-time Alerts:** Integrated to flag suspicious activity directly to the user.

`[Optional: Link to Detailed Architecture Document or Diagram]`

</details>

---

## ⚙️ Installation Guide

<details>
<summary><strong>⚡ Click to expand Installation Steps</strong></summary>

### >> Prerequisites

* **OS:** Linux (Tested primarily on Fedora, adaptable to other distros).
* **Compiler:** `g++` (supporting C++11 or later).
* **Build Tool:** `make`.
* **Libraries:**
    * OpenSSL: `libssl-dev`, `libcrypto-dev` (Debian/Ubuntu) or `openssl-devel` (Fedora/CentOS).
    * Qt5: `qt5-default`, `qtbase5-dev` (Debian/Ubuntu) or `qt5-qtbase-devel` (Fedora/CentOS). Adjust package names based on your distro.
* **ML (Future):** Python 3.x, `pip`, `scikit-learn`, `joblib`.

### >> Build Process

1.  **Clone Repository:**
    ```bash
    git clone [https://github.com/yourusername/UltraSecureTextEncryption.git](https://github.com/Hitesh-Jangid/SecureMessage.git) 
    ```
2.  **Compile:**
    ```bash
    # Navigate to the source code directory
        make clean && make
    ```
    *This generates executables: `ServerApp`, `ClientApp`, `GUIApp` in the build directory.*

</details>

---

## ▶️ Running the Application

<details>
<summary><strong>🚀 Click to expand Usage Instructions</strong></summary>

1.  **Start the Server:**
    * Open a terminal.
    * Navigate to the directory with the `ServerApp` executable.
    * Run: `./ServerApp`
    * Enter a desired port number (e.g., `4444`) when prompted. Keep this terminal open.

2.  **Run CLI Clients:**
    * Open a *new* terminal for each client.
    * Navigate to the directory with the `ClientApp` executable.
    * Run: `./ClientApp`
    * Follow prompts for: Server IP (e.g., `127.0.0.1`), Server Port (`4444`), Unique Username.
    * Use the interactive menu to send/receive messages.

3.  **Run the GUI Client:**
    * Open a terminal (or use your desktop environment's launcher).
    * Navigate to the directory with the `GUIApp` executable.
    * Run: `./GUIApp`
    * A setup dialog will appear. Enter:
        * Number of Users (minimum 2).
        * Server IP and Port.
        * Usernames for each chat window.
    * Chat windows will open. Messages sent from one user appear only in their window and the recipient's window.

</details>

---

## 📊 Security Posture vs. Alternatives

| Feature                    | Signal          | WhatsApp        | **UltraSecureTextEncryption** |
| :------------------------- | :-------------: | :-------------: | :-------------------------------------: |
| **E2E Encryption** | Signal Protocol | Signal Protocol | **AES-256 + RSA-2048 (Hybrid)** |
| **Digital Signatures** | Integrated\* | ❌ No           | **✅ Explicit RSA + SHA-256** |
| **Open Source** | ✅ Yes          | ❌ No           | **✅ Yes (MIT License)** |
| **Metadata Handling** | Advanced        | Limited         | **🛡️ Minimal & User-Controlled** |
| **ML Anomaly Detection** | Planned         | ❌ No           | **🧠 Planned (Real-Time)** |
| **Forward Secrecy** | ✅ Yes          | ✅ Yes          | **⏳ Planned Enhancement** |

---

## 🗺️ Project Roadmap

* [ ] **🧠 Implement ML Anomaly Detection Module:** Integrate `scikit-learn` based pattern analysis.
* [ ] **🎨 GUI Enhancements:** Chat bubbles, user status, notifications, improved theming.
* [ ] **🤝 Group Chat Functionality:** Extend protocol and UI for multi-recipient groups.
* [ ] **⏳ Add Forward Secrecy:** Implement ECDH or similar for session key exchange.
* [ ] **🔗 Refine Network Protocol:** Enhance efficiency and robustness.
* [ ] **📱 Explore Cross-Platform:** Investigate mobile/web client possibilities.

---

## 🤝 Contributing & Contact

We welcome contributions!
* **🧑‍💻 Lead Developer:** Hitesh Jangid
* **🐛 Report Issues:** **[Submit an Issue](https://github.com/Hitesh-Jangid/SecureMessage/issues)** 
* **💡 Feature Requests:** **[Suggest an Idea](https://github.com/Hitesh-Jangid/SecureMessage/issues)** 
* **🐙 Project Repository:** **[github.com/Hitesh-Jangid/SecureMessage](https://github.com/Hitesh-Jangid/SecureMessage)** 
* **📧 Contact:** `hiteshjangid@duck.com`

<div align="center">

---

Powered by Payar, Passion, and Purpose with Privacy — Securing your Secrets with Strength, and built on Trust, Transparency, and Truth.✨
* **🧑‍💻** Hitesh Jangid

</div>
