import sys, os
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QPalette, QColor, QFont
from collections import defaultdict

from iptables_manager import IptablesManager, Rule
from draggable_table import DraggableTableWidget
from rule_dialog import RuleDialog

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IPTables Forge - Firewall Manager")
        self.resize(1200, 800)
        
        QApplication.setFont(QFont("Segoe UI", 10))

        self.manager = IptablesManager()
        self.all_rules = []
        self.is_dark_mode = True

        self.setup_ui()
        self.apply_theme()
        self.load_initial_rules()

    def setup_ui(self):
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        top = QHBoxLayout()
        self.add_btn = QPushButton("+ AGGIUNGI")
        self.add_btn.setMinimumHeight(38)
        self.add_btn.clicked.connect(self.add_rule)
        
        self.edit_btn = QPushButton("✎ MODIFICA")
        self.edit_btn.setMinimumHeight(38)
        self.edit_btn.clicked.connect(self.edit_rule)

        self.remove_btn = QPushButton("RIMUOVI")
        self.remove_btn.setMinimumHeight(38)
        self.remove_btn.clicked.connect(self.remove_rule)
        
        top.addWidget(self.add_btn)
        top.addWidget(self.edit_btn)
        top.addWidget(self.remove_btn)
        top.addSpacing(30)
        
        top.addWidget(QLabel("CHAIN:"))
        self.chain_filter = QComboBox()
        self.chain_filter.setMinimumWidth(180)
        self.chain_filter.setMinimumHeight(38)
        self.chain_filter.addItem("TUTTE LE CHAIN")
        self.chain_filter.currentTextChanged.connect(self.populate_table)
        top.addWidget(self.chain_filter)
        
        top.addStretch()
        
        self.persistence_check = QCheckBox("PERSISTENZA")
        self.persistence_check.setChecked(True)
        top.addWidget(self.persistence_check)

        self.ipv6_check = QCheckBox("IPv6")
        self.ipv6_check.stateChanged.connect(self.toggle_ipv6)
        top.addWidget(self.ipv6_check)
        
        self.theme_btn = QPushButton("MODALITÀ CHIARA")
        self.theme_btn.setMinimumHeight(38)
        self.theme_btn.clicked.connect(self.toggle_theme)
        top.addWidget(self.theme_btn)
        
        self.apply_btn = QPushButton("APPLICA E SALVA")
        self.apply_btn.setObjectName("applyButton")
        self.apply_btn.setMinimumHeight(38)
        self.apply_btn.setMinimumWidth(180)
        self.apply_btn.clicked.connect(self.apply_changes)
        top.addWidget(self.apply_btn)
        
        layout.addLayout(top)
        
        self.rules_table = DraggableTableWidget()
        self.rules_table.setColumnCount(10)
        self.rules_table.setHorizontalHeaderLabels(["TABELLA", "CHAIN", "PROTO", "SORGENTE", "S.PORT", "DEST", "D.PORT", "STATO", "COMMENTO", "AZIONE"])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setShowGrid(False)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.itemDropped.connect(self.handle_reorder)
        self.rules_table.cellDoubleClicked.connect(self.edit_rule)
        layout.addWidget(self.rules_table)
        
        self.setCentralWidget(central)

    def apply_theme(self):
        if self.is_dark_mode:
            self.theme_btn.setText("MODALITÀ CHIARA")
            style = """
                QMainWindow, QDialog { background-color: #1a1b1e; color: #e0e0e0; }
                QWidget { background-color: #1a1b1e; color: #e0e0e0; }
                QTableWidget { background-color: #25262b; alternate-background-color: #2c2e33; color: #e0e0e0; gridline-color: transparent; border: 1px solid #373a40; border-radius: 8px; }
                QHeaderView::section { background-color: #1a1b1e; color: #909296; padding: 10px; border: none; font-weight: bold; }
                QLineEdit, QComboBox { background-color: #25262b; color: #ffffff; border: 1px solid #373a40; border-radius: 4px; padding: 5px; }
                QPushButton { background-color: #373a40; color: white; border-radius: 4px; padding: 5px 15px; border: 1px solid #4d4f56; font-weight: bold; }
                #applyButton { background-color: #2b8a3e; border: none; }
                QCheckBox { color: #e0e0e0; font-weight: bold; }
                QCheckBox::indicator { width: 18px; height: 18px; background-color: #373a40; border: 2px solid #4d4f56; border-radius: 4px; }
                QCheckBox::indicator:checked { background-color: #339af0; border: 2px solid #339af0; }
            """
        else:
            self.theme_btn.setText("MODALITÀ SCURA")
            style = """
                QMainWindow, QDialog { background-color: #f8f9fa; color: #212529; }
                QTableWidget { background-color: #ffffff; alternate-background-color: #f1f3f5; color: #212529; border: 1px solid #dee2e6; }
                QPushButton { background-color: #f1f3f5; border: 1px solid #ced4da; color: #495057; font-weight: bold; }
                #applyButton { background-color: #40c057; color: white; }
                QCheckBox { color: #495057; font-weight: bold; }
            """
        QApplication.instance().setStyleSheet(style)

    def update_chain_filter_list(self):
        chains = {"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}
        for r in self.all_rules: chains.add(r.chain)
        self.chain_filter.blockSignals(True)
        current = self.chain_filter.currentText()
        self.chain_filter.clear()
        self.chain_filter.addItem("TUTTE LE CHAIN")
        self.chain_filter.addItems(sorted(list(chains)))
        if current in chains or current == "TUTTE LE CHAIN": self.chain_filter.setCurrentText(current)
        self.chain_filter.blockSignals(False)

    def load_initial_rules(self):
        raw_data = self.manager.load_rules()
        self.all_rules = []
        for table in raw_data:
            for chain in raw_data[table]:
                self.all_rules.extend(raw_data[table][chain])
        self.update_chain_filter_list()
        self.populate_table()

    def populate_table(self):
        self.rules_table.setRowCount(0)
        self.rules_table.clearContents()
        filter_text = self.chain_filter.currentText()
        self.visible_rules = [r for r in self.all_rules if filter_text == "TUTTE LE CHAIN" or r.chain == filter_text]
        for i, r in enumerate(self.visible_rules):
            self.rules_table.insertRow(i)
            row_vals = [r.table, r.chain, r.protocol, r.source, r.sport or "", r.destination, r.dport or "", r.state or "", r.comment or "", r.target]
            for col, val in enumerate(row_vals):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if col == 9: 
                    if val == "ACCEPT": item.setForeground(QColor("#40c057"))
                    elif val in ["DROP", "REJECT"]: item.setForeground(QColor("#fa5252"))
                self.rules_table.setItem(i, col, item)

    def handle_reorder(self, src_row, dst_row):
        if src_row == dst_row: return
        moved_rule = self.all_rules.pop(src_row)
        self.all_rules.insert(dst_row, moved_rule)
        self.populate_table()

    def add_rule(self):
        dialog = RuleDialog(self)
        if dialog.exec():
            self.all_rules.append(dialog.get_rule())
            self.update_chain_filter_list()
            self.populate_table()

    def edit_rule(self):
        row = self.rules_table.currentRow()
        if row < 0: return
        original_rule = self.visible_rules[row]
        global_idx = self.all_rules.index(original_rule)
        dialog = RuleDialog(self, rule=original_rule)
        if dialog.exec():
            self.all_rules[global_idx] = dialog.get_rule()
            self.update_chain_filter_list()
            self.populate_table()

    def remove_rule(self):
        row = self.rules_table.currentRow()
        if row >= 0:
            self.all_rules.remove(self.visible_rules[row])
            self.update_chain_filter_list()
            self.populate_table()

    def apply_changes(self):
        struct = defaultdict(lambda: defaultdict(list))
        for r in self.all_rules: struct[r.table][r.chain].append(r)
        ok, err = self.manager.apply_rules(struct)
        if ok:
            msg = "Configurazione kernel aggiornata."
            if self.persistence_check.isChecked():
                save_ok, save_err = self.manager.save_to_system()
                msg += "\n✅ Servizio Systemd configurato e abilitato." if save_ok else f"\n❌ Errore Systemd: {save_err}"
            else:
                self.manager.disable_persistence()
                msg += "\n⚠️ Persistenza disabilitata e servizio rimosso."
            QMessageBox.information(self, "Firewall", msg)
        else:
            QMessageBox.critical(self, "Errore", err)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.apply_theme()

    def toggle_ipv6(self, state):
        self.manager.is_ipv6_mode = (state == Qt.CheckState.Checked.value)
        self.load_initial_rules()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Usa sudo."); sys.exit(1)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
