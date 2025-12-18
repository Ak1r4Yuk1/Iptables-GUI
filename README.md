# IPTables Forge - Firewall Manager 🛡️

**IPTables Forge** è un'interfaccia grafica (GUI) moderna e intuitiva basata su **PyQt6** per gestire il firewall Linux. Permette di amministrare le regole di `iptables` e `ip6tables` senza dover scrivere complessi comandi nel terminale, offrendo funzionalità avanzate come il riordino tramite Drag & Drop e la persistenza automatica al boot.



## ✨ Caratteristiche Principali

* **Gestione Completa Tabelle:** Supporta le tabelle `filter`, `nat`, `mangle` e `raw`.
* **Drag & Drop Intelligent:** Trascina le righe della tabella per cambiare l'ordine delle regole (e quindi la loro priorità nel kernel).
* **Supporto Dual Stack:** Gestione separata e integrata per **IPv4** e **IPv6**.
* **Persistenza al Boot:** Crea e abilita automaticamente un servizio Systemd (`iptables-forge.service`) per ricaricare le tue regole ad ogni avvio.
* **Interfaccia Personalizzabile:** Modalità Scura (Dark Mode) di default per il massimo comfort visivo, con possibilità di passare alla Modalità Chiara.
* **Editor Dettagliato:** Dialog di configurazione per gestire protocolli, porte, stati (`state`), commenti e target (ACCEPT, DROP, REJECT, LOG, ecc.).

## 🚀 Requisiti

Il software richiede un sistema operativo Linux e Python 3.10+.

### Dipendenze di sistema
Assicurati che i tool di base siano installati (solitamente presenti di default):
* `iptables`
* `ip6tables`

## 🛠️ Installazione

1.  **Clona il repository:**
    ```bash
    git clone [https://github.com/Ak1r4Yuk1/Iptables-GUI.git](https://github.com/Ak1r4Yuk1/Iptables-GUI.git)
    cd Iptables-GUI
    ```

2.  **Installa le dipendenze Python:**
    Si consiglia l'uso di un ambiente virtuale, ma puoi installare direttamente tramite:
    ```bash
    sudo pip install PyQt6 (in alcuni casi devi aggiungere anche --break-system-packages oppure sudo apt install python3-PyQt6 oppure sudo pacman -S python-PyQt6)
    ```

## 🚥 Come Avviare

Poiché `iptables` interagisce direttamente con il kernel Linux, il programma richiede **privilegi di root**.

Avvia l'applicazione con `sudo`:
```bash
sudo python3 main.py
