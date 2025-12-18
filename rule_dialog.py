from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox, QLabel

class RuleDialog(QDialog):
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.setWindowTitle("Dettagli Regola")
        self.setMinimumWidth(480)
        
        self.table_chains = {
            "filter": ["INPUT", "FORWARD", "OUTPUT"],
            "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
            "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"],
            "raw": ["PREROUTING", "OUTPUT"]
        }
        
        self.setup_ui()
        if rule:
            self.fill_data(rule)
        else:
            self.update_chains("filter")

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        title = QLabel("CONFIGURAZIONE PARAMETRI")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #339af0; letter-spacing: 1px;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(12)

        self.table_cb = QComboBox()
        self.table_cb.addItems(list(self.table_chains.keys()))
        self.table_cb.currentTextChanged.connect(self.update_chains)
        
        self.chain_cb = QComboBox()
        self.chain_cb.setEditable(True)

        self.proto_cb = QComboBox()
        self.proto_cb.addItems(["all", "tcp", "udp", "icmp", "icmpv6"])

        self.src_input = QLineEdit("any")
        self.sport_input = QLineEdit()
        self.dst_input = QLineEdit("any")
        self.dport_input = QLineEdit()
        self.state_input = QLineEdit()
        self.target_cb = QComboBox()
        self.target_cb.addItems(["ACCEPT", "DROP", "REJECT", "LOG", "MASQUERADE", "DNAT", "SNAT"])
        self.comment_input = QLineEdit()

        form.addRow("TABELLA:", self.table_cb)
        form.addRow("CHAIN:", self.chain_cb)
        form.addRow("PROTOCOLLO:", self.proto_cb)
        form.addRow("SORGENTE:", self.src_input)
        form.addRow("PORTA SORG.:", self.sport_input)
        form.addRow("DESTINAZIONE:", self.dst_input)
        form.addRow("PORTA DEST.:", self.dport_input)
        form.addRow("STATO:", self.state_input)
        form.addRow("TARGET:", self.target_cb)
        form.addRow("COMMENTO:", self.comment_input)

        layout.addLayout(form)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def update_chains(self, table_name):
        self.chain_cb.clear()
        if table_name in self.table_chains:
            self.chain_cb.addItems(self.table_chains[table_name])

    def fill_data(self, rule):
        self.table_cb.setCurrentText(rule.table)
        self.update_chains(rule.table)
        self.chain_cb.setCurrentText(rule.chain)
        self.proto_cb.setCurrentText(rule.protocol)
        self.src_input.setText(rule.source)
        self.sport_input.setText(rule.sport or "")
        self.dst_input.setText(rule.destination)
        self.dport_input.setText(rule.dport or "")
        self.state_input.setText(rule.state or "")
        self.target_cb.setCurrentText(rule.target)
        self.comment_input.setText(rule.comment or "")

    def get_rule(self):
        from iptables_manager import Rule
        return Rule(
            table=self.table_cb.currentText(),
            chain=self.chain_cb.currentText(),
            protocol=self.proto_cb.currentText(),
            source=self.src_input.text(),
            destination=self.dst_input.text(),
            target=self.target_cb.currentText(),
            sport=self.sport_input.text() or None,
            dport=self.dport_input.text() or None,
            state=self.state_input.text() or None,
            comment=self.comment_input.text()
        )
