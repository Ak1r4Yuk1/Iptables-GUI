from PyQt6.QtWidgets import QTableWidget, QAbstractItemView
from PyQt6.QtCore import Qt, pyqtSignal

class DraggableTableWidget(QTableWidget):
    itemDropped = pyqtSignal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropOverwriteMode(False)
        self.setDropIndicatorShown(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)

    def dropEvent(self, event):
        if not event.source() == self: return
        source_row = self.currentRow()
        drop_row = self.indexAt(event.position().toPoint()).row()
        if drop_row == -1: drop_row = self.rowCount() - 1
        super().dropEvent(event)
        self.itemDropped.emit(source_row, drop_row)
