"""Qt worker for running scans without blocking the main window."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from guinmap.application.scan_service import ScanExecutionError, ScanService
from guinmap.domain.scan_profile import ScanProfile


class ScanWorker(QObject):
    output_received = Signal(str)
    completed = Signal(object)
    failed = Signal(str, object)
    finished = Signal()

    def __init__(self, scan_service: ScanService, profile: ScanProfile) -> None:
        super().__init__()
        self._scan_service = scan_service
        self._profile = profile

    @Slot()
    def run(self) -> None:
        try:
            execution = self._scan_service.run(self._profile, on_output=self.output_received.emit)
        except ScanExecutionError as exc:
            self.failed.emit(str(exc), exc.execution)
        except Exception as exc:
            self.failed.emit(str(exc), None)
        else:
            self.completed.emit(execution)
        finally:
            self.finished.emit()