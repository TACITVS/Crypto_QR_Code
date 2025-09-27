"""PyQt5 user interface for the Secure QR Code Tool."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

from PyQt5.QtCore import QObject, QThread, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QImage, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QGroupBox,
    QHBoxLayout,
    QWidget,
)

from .config import AppConfig, CameraConfig, StyleConfig
from .icon import create_icon
from .network import is_online
from .qr import QRCodeManager
from .security import CryptoManager, MnemonicManager, SecureString
from .state import AppState


class CryptoWorker(QObject):  # pragma: no cover - requires Qt event loop
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, crypto: CryptoManager, mode: str, data: Any, password: SecureString):
        super().__init__()
        self._crypto = crypto
        self._mode = mode
        self._password = password.copy()
        self._data = data.copy() if isinstance(data, SecureString) else data

    def run(self) -> None:
        try:
            if self._mode == "encrypt":
                result = self._crypto.encrypt(self._data, self._password)
            elif self._mode == "decrypt":
                result = self._crypto.decrypt(self._data, self._password)
            else:  # pragma: no cover - defensive
                raise ValueError(f"Unknown crypto mode: {self._mode}")
        except Exception as exc:
            self.error.emit(str(exc))
        else:
            self.finished.emit(result)
        finally:
            if isinstance(self._data, SecureString):
                self._data.clear()
            self._password.clear()


class LockScreen(QWidget):  # pragma: no cover - requires Qt event loop
    unlocked = pyqtSignal(SecureString)

    def __init__(self, config: AppConfig, style: StyleConfig):
        super().__init__()
        self._config = config
        self._style = style
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        panel = QWidget()
        panel.setMaximumWidth(450)
        panel.setObjectName("CentralPanel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setSpacing(15)

        title = QLabel("Set Master Password")
        title.setObjectName("HeaderLabel")
        title.setAlignment(Qt.AlignCenter)

        info = QLabel(
            "Create a master password for this session.\n"
            "This password is NOT saved and will encrypt all data."
        )
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignCenter)
        info.setObjectName("SubtleLabel")

        self._password_input = QLineEdit()
        self._password_input.setEchoMode(QLineEdit.Password)
        self._password_input.setPlaceholderText("Enter strong password...")
        self._password_input.setMinimumHeight(40)

        self._confirm_input = QLineEdit()
        self._confirm_input.setEchoMode(QLineEdit.Password)
        self._confirm_input.setPlaceholderText("Confirm password...")
        self._confirm_input.setMinimumHeight(40)

        unlock_btn = QPushButton("Set Password & Unlock")
        unlock_btn.setObjectName("AccentButton")
        unlock_btn.setMinimumHeight(45)

        panel_layout.addWidget(title)
        panel_layout.addWidget(info)
        panel_layout.addWidget(QLabel("Password:"))
        panel_layout.addWidget(self._password_input)
        panel_layout.addWidget(QLabel("Confirm:"))
        panel_layout.addWidget(self._confirm_input)
        panel_layout.addWidget(unlock_btn)

        layout.addWidget(panel)

        unlock_btn.clicked.connect(self._validate_password)
        self._password_input.returnPressed.connect(self._validate_password)
        self._confirm_input.returnPressed.connect(self._validate_password)

    def _validate_password(self) -> None:
        password = self._password_input.text()
        confirm = self._confirm_input.text()

        if len(password) < self._config.min_password_length:
            QMessageBox.warning(
                self,
                "Weak Password",
                f"Password must be at least {self._config.min_password_length} characters.",
            )
            return

        if password != confirm:
            QMessageBox.warning(self, "Mismatch", "Passwords don't match.")
            return

        secure = SecureString(password)
        self._password_input.clear()
        self._confirm_input.clear()
        self.unlocked.emit(secure)


class CameraWorker(QObject):  # pragma: no cover - requires Qt event loop
    """Background worker that streams frames from the system camera."""

    frame_captured = pyqtSignal(object)
    decoded = pyqtSignal(bytes)
    status = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, config: AppConfig, camera_config: CameraConfig):
        super().__init__()
        self._config = config
        self._camera_config = camera_config
        self._running = False
        self._cv2 = None
        self._pyzbar = None

    def stop(self) -> None:
        self._running = False

    # The imports inside ``run`` keep the module importable in environments
    # without optional camera dependencies.  The method is intentionally
    # verbose to provide actionable status updates to the UI.
    def run(self) -> None:
        try:
            import cv2  # type: ignore
            from pyzbar import pyzbar  # type: ignore
        except Exception:
            self.status.emit("Camera dependencies not installed")
            self.finished.emit()
            return

        self._cv2 = cv2
        self._pyzbar = pyzbar

        capture = self._open_capture()
        if capture is None:
            self.status.emit("Unable to access camera")
            self.finished.emit()
            return

        self._running = True
        frame_skip = max(1, self._config.camera_frame_skip)
        frame_counter = 0

        self.status.emit("Camera active – align QR code")

        try:
            while self._running:
                success, frame = capture.read()
                if not success or frame is None:
                    self.status.emit("Camera feed unavailable")
                    break

                frame = self._resize_frame(frame)
                self.frame_captured.emit(frame)

                frame_counter += 1
                if frame_counter % frame_skip:
                    continue

                decoded = self._decode_frame(frame)
                if decoded:
                    self.decoded.emit(decoded)
                    break
        finally:
            self._running = False
            capture.release()
            self.finished.emit()

    def _open_capture(self):
        assert self._cv2 is not None
        config = self._camera_config

        default_backend = getattr(self._cv2, "CAP_ANY", 0)
        for backend in config.get_backends() or [default_backend]:
            for index in config.get_indices():
                try:
                    capture = self._cv2.VideoCapture(index, backend)
                except TypeError:
                    capture = self._cv2.VideoCapture(index)
                if not capture or not capture.isOpened():
                    if capture:
                        capture.release()
                    continue

                capture.set(self._cv2.CAP_PROP_FRAME_WIDTH, config.width)
                capture.set(self._cv2.CAP_PROP_FRAME_HEIGHT, config.height)
                return capture
        return None

    def _resize_frame(self, frame):
        assert self._cv2 is not None
        max_dim = max(frame.shape[:2])
        limit = self._config.max_frame_size
        if max_dim <= limit:
            return frame

        scale = limit / float(max_dim)
        new_size = (int(frame.shape[1] * scale), int(frame.shape[0] * scale))
        return self._cv2.resize(frame, new_size)

    def _decode_frame(self, frame):
        assert self._cv2 is not None and self._pyzbar is not None
        gray = self._cv2.cvtColor(frame, self._cv2.COLOR_BGR2GRAY)
        candidates = [
            gray,
            self._cv2.GaussianBlur(gray, (5, 5), 0),
            self._cv2.threshold(
                gray,
                0,
                255,
                self._cv2.THRESH_BINARY + self._cv2.THRESH_OTSU,
            )[1],
        ]

        for processed in candidates:
            decoded = self._pyzbar.decode(processed)
            if decoded:
                return QRCodeManager.decode_qr_payload(decoded[0].data)
        return None


class MainWindow(QWidget):  # pragma: no cover - requires Qt event loop
    def __init__(
        self,
        app: "SecureQRApp",
        config: AppConfig,
        state: AppState,
        style: StyleConfig,
        camera_config: CameraConfig,
    ):
        super().__init__()
        self._app = app
        self._config = config
        self._state = state
        self._style = style
        self._camera_config = camera_config

        self._crypto = CryptoManager(config)
        self._mnemonic = MnemonicManager(config)
        self._qr = QRCodeManager(config)
        self._mnemonic_word_count = self._mnemonic.default_word_count

        self._camera_display: QLabel | None = None
        self._camera_status: QLabel | None = None
        self._camera_start_btn: QPushButton | None = None
        self._camera_stop_btn: QPushButton | None = None
        self._camera_thread: QThread | None = None
        self._camera_worker: CameraWorker | None = None
        self._cv2_module = None

        self._mnemonic_selector: QComboBox | None = None
        self._mnemonic_generate_btn: QPushButton | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        self._network_banner = QLabel()
        self._network_banner.setAlignment(Qt.AlignCenter)
        self._network_banner.setStyleSheet("padding: 8px; font-weight: bold;")
        self._update_network_status()

        self._tabs = QTabWidget()
        self._tabs.addTab(self._create_generate_tab(), "Generate & Encrypt")
        self._tabs.addTab(self._create_decrypt_tab(), "Read & Decrypt")

        layout.addWidget(self._network_banner)
        layout.addWidget(self._tabs)

        self._network_timer = QTimer()
        self._network_timer.timeout.connect(self._update_network_status)
        self._network_timer.start(self._config.network_check_interval_ms)

    def _update_network_status(self) -> None:
        self._state.is_online = is_online()
        if self._state.is_online:
            self._network_banner.setText("⚠️ ONLINE - Disconnect for maximum security")
            self._network_banner.setObjectName("WarningLabel")
        else:
            self._network_banner.setText("✔️ OFFLINE - Air-gapped and secure")
            self._network_banner.setObjectName("SuccessLabel")
        self._network_banner.style().polish(self._network_banner)

    def _create_generate_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.addStretch()

        panel = QWidget()
        panel.setObjectName("CentralPanel")
        panel.setMaximumWidth(800)
        panel_layout = QVBoxLayout(panel)

        group = QGroupBox("Step 1: Generate Mnemonic")
        group_layout = QVBoxLayout()

        selector_row = QHBoxLayout()
        selector_label = QLabel("Mnemonic length:")
        selector_label.setObjectName("SubtleLabel")
        self._mnemonic_selector = QComboBox()
        for count in MnemonicManager.valid_word_counts():
            self._mnemonic_selector.addItem(f"{count} words", count)
        default_index = self._mnemonic_selector.findData(self._mnemonic_word_count)
        if default_index >= 0:
            self._mnemonic_selector.setCurrentIndex(default_index)
        self._mnemonic_selector.currentIndexChanged.connect(
            self._on_mnemonic_word_count_changed
        )
        selector_row.addWidget(selector_label)
        selector_row.addWidget(self._mnemonic_selector)

        self._mnemonic_display = QTextEdit()
        self._mnemonic_display.setReadOnly(True)
        self._mnemonic_display.setMinimumHeight(110)
        self._mnemonic_display.setFont(QFont(self._style.font_mono, 11))

        self._checksum_label = QLabel("Checksum: ----")
        self._checksum_label.setObjectName("ChecksumLabel")
        self._checksum_label.setAlignment(Qt.AlignCenter)

        self._mnemonic_generate_btn = QPushButton()
        self._mnemonic_generate_btn.setObjectName("AccentButton")
        self._mnemonic_generate_btn.clicked.connect(self._generate_mnemonic)

        self._update_mnemonic_ui_texts()

        group_layout.addLayout(selector_row)
        group_layout.addWidget(self._mnemonic_generate_btn)
        group_layout.addWidget(QLabel("Write down this phrase and checksum:"))
        group_layout.addWidget(self._mnemonic_display)
        group_layout.addWidget(self._checksum_label)
        group.setLayout(group_layout)

        save_group = QGroupBox("Step 2: Save Encrypted Data")
        save_layout = QVBoxLayout()

        self._qr_preview = QLabel("QR code will appear here")
        self._qr_preview.setObjectName("qrDisplayLabel")
        self._qr_preview.setAlignment(Qt.AlignCenter)
        self._qr_preview.setMinimumSize(256, 256)

        if self._qr.is_available():
            save_qr_btn = QPushButton("Save as QR Image")
            save_qr_btn.clicked.connect(self._save_as_qr)
            save_layout.addWidget(save_qr_btn)
        else:
            info = QLabel("Install 'segno' for QR support: pip install segno[pil]")
            info.setWordWrap(True)
            save_layout.addWidget(info)

        save_json_btn = QPushButton("Save as JSON File")
        save_json_btn.clicked.connect(self._save_as_json)

        save_layout.addWidget(self._qr_preview)
        save_layout.addWidget(save_json_btn)
        save_group.setLayout(save_layout)

        panel_layout.addWidget(group)
        panel_layout.addWidget(save_group)
        layout.addWidget(panel)
        layout.addStretch()

        return tab

    def _update_mnemonic_ui_texts(self) -> None:
        placeholder = (
            f"Click 'Generate' to create a new {self._mnemonic_word_count}-word recovery phrase..."
        )
        self._mnemonic_display.setPlaceholderText(placeholder)
        if self._mnemonic_generate_btn is not None:
            self._mnemonic_generate_btn.setText(
                f"Generate New {self._mnemonic_word_count}-Word Mnemonic"
            )

    def _on_mnemonic_word_count_changed(self, index: int) -> None:
        if self._mnemonic_selector is None:
            return
        count = self._mnemonic_selector.itemData(index)
        if count is None:
            return
        self._mnemonic_word_count = int(count)
        self._mnemonic_display.clear()
        self._checksum_label.setText("Checksum: ----")
        self._update_mnemonic_ui_texts()

    def _create_decrypt_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.addStretch()

        panel = QWidget()
        panel.setObjectName("CentralPanel")
        panel.setMaximumWidth(800)
        panel_layout = QVBoxLayout(panel)

        load_group = QGroupBox("Step 1: Load Encrypted Data")
        load_layout = QVBoxLayout()

        self._load_stack = QStackedWidget()

        btn_page = QWidget()
        btn_layout = QVBoxLayout(btn_page)

        load_qr_btn = QPushButton("Load QR Image File")
        load_qr_btn.clicked.connect(self._load_qr_file)
        btn_layout.addWidget(load_qr_btn)

        load_json_btn = QPushButton("Load JSON File")
        load_json_btn.clicked.connect(self._load_json_file)
        btn_layout.addWidget(load_json_btn)

        self._load_stack.addWidget(btn_page)

        self._loaded_label = QLabel("No data loaded")
        self._loaded_label.setAlignment(Qt.AlignCenter)

        load_layout.addWidget(self._load_stack)
        load_layout.addWidget(self._loaded_label)
        load_group.setLayout(load_layout)

        camera_group = self._create_camera_group()

        decrypt_group = QGroupBox("Step 2: Decrypted Data")
        decrypt_layout = QVBoxLayout()

        self._decrypted_display = QTextEdit()
        self._decrypted_display.setReadOnly(True)
        self._decrypted_display.setMinimumHeight(110)
        self._decrypted_display.setFont(QFont(self._style.font_mono, 11))
        self._decrypted_display.setPlaceholderText("Decrypted content will appear here...")

        self._verify_checksum = QLabel("Checksum: ----")
        self._verify_checksum.setAlignment(Qt.AlignCenter)
        self._verify_checksum.setObjectName("ChecksumLabel")

        decrypt_layout.addWidget(QLabel("Decrypted Mnemonic:"))
        decrypt_layout.addWidget(self._decrypted_display)
        decrypt_layout.addWidget(self._verify_checksum)
        decrypt_group.setLayout(decrypt_layout)

        panel_layout.addWidget(load_group)
        if camera_group is not None:
            panel_layout.addWidget(camera_group)
        panel_layout.addWidget(decrypt_group)
        layout.addWidget(panel)
        layout.addStretch()

        return tab

    def _create_camera_group(self) -> QWidget | None:
        try:
            import cv2  # type: ignore
        except Exception:
            self._state.camera_available = False
            return None

        try:
            from pyzbar import pyzbar  # type: ignore  # noqa: F401
        except Exception:
            self._state.camera_available = False
            return None

        self._state.camera_available = True
        self._cv2_module = cv2

        group = QGroupBox("Or Scan Using Camera")
        layout = QVBoxLayout()

        self._camera_display = QLabel("Camera preview will appear here")
        self._camera_display.setObjectName("qrDisplayLabel")
        self._camera_display.setAlignment(Qt.AlignCenter)
        self._camera_display.setMinimumSize(320, 240)

        self._camera_status = QLabel("Camera idle")
        self._camera_status.setAlignment(Qt.AlignCenter)
        self._camera_status.setObjectName("SubtleLabel")

        button_row = QHBoxLayout()
        self._camera_start_btn = QPushButton("Start Camera Scan")
        self._camera_stop_btn = QPushButton("Stop Camera")
        self._camera_stop_btn.setEnabled(False)

        self._camera_start_btn.clicked.connect(self._start_camera)
        self._camera_stop_btn.clicked.connect(self._stop_camera)

        button_row.addWidget(self._camera_start_btn)
        button_row.addWidget(self._camera_stop_btn)

        layout.addWidget(self._camera_display)
        layout.addLayout(button_row)
        layout.addWidget(self._camera_status)

        group.setLayout(layout)
        return group

    def _generate_mnemonic(self) -> None:
        try:
            mnemonic = self._mnemonic.generate(self._mnemonic_word_count)
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Generation failed: {exc}")
            return

        numbered = "\n".join(
            f"{index + 1:>2}. {word}"
            for index, word in enumerate(mnemonic.split())
        )
        self._mnemonic_display.setText(numbered)
        self._checksum_label.setText(f"Checksum: {MnemonicManager.checksum(mnemonic)}")

        if not self._state.master_password:
            QMessageBox.critical(self, "Error", "No master password set")
            return

        self._app.start_crypto("encrypt", SecureString(mnemonic), self._state.master_password)

    def handle_encrypted(self, result: tuple[Dict[str, str], bytes]) -> None:
        payload_dict, payload_bytes = result
        self._state.current_encrypted_payload = payload_dict
        self._state.current_encrypted_payload_bytes = payload_bytes
        if not self._qr.is_available():
            self._qr_preview.setText("QR generation not available")
            return

        try:
            pixmap = self._qr.to_qpixmap(payload_bytes)
        except Exception as exc:
            self._qr_preview.setText(f"QR preview failed: {exc}")
            return

        scaled = pixmap.scaled(self._qr_preview.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self._qr_preview.setPixmap(scaled)

    def _save_as_qr(self) -> None:
        if not self._state.current_encrypted_payload_bytes:
            QMessageBox.warning(self, "Error", "No data to save")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save QR Code", "", "PNG Images (*.png)")
        if not path:
            return

        try:
            self._qr.save_png(self._state.current_encrypted_payload_bytes, path)
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Save failed: {exc}")
        else:
            QMessageBox.information(self, "Success", "QR code saved successfully")

    def _save_as_json(self) -> None:
        if not self._state.current_encrypted_payload:
            QMessageBox.warning(self, "Error", "No data to save")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "", "JSON Files (*.json)")
        if not path:
            return

        data = {
            "app": self._config.app_name,
            "version": self._config.app_version,
            "payload": self._state.current_encrypted_payload,
        }

        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
        except OSError as exc:
            QMessageBox.critical(self, "Error", f"Save failed: {exc}")
        else:
            QMessageBox.information(self, "Success", "JSON saved successfully")

    def _load_qr_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open QR Image", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if not path:
            return

        data = self._qr.read_from_file(path)
        if not data:
            QMessageBox.critical(self, "Error", "Failed to read QR from image")
            return

        self._process_loaded_data(data, f"Loaded: {Path(path).name}")

    def _load_json_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open JSON", "", "JSON Files (*.json)")
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, "Error", f"Load failed: {exc}")
            return

        if "payload" not in data:
            QMessageBox.critical(self, "Error", "Invalid JSON format - missing 'payload'")
            return

        self._process_loaded_data(data["payload"], f"Loaded: {Path(path).name}")

    def _process_loaded_data(self, payload: object, source: str) -> None:
        processed: object = payload
        if isinstance(payload, str):
            try:
                processed = json.loads(payload)
            except json.JSONDecodeError as exc:
                QMessageBox.critical(self, "Error", f"Invalid JSON data: {exc}")
                return
        elif isinstance(payload, Mapping):
            processed = dict(payload)
        elif isinstance(payload, (bytes, bytearray)):
            processed = bytes(payload)
        else:
            QMessageBox.critical(self, "Error", "Unsupported payload format")
            return

        self._loaded_label.setText(source)

        if not self._state.master_password:
            QMessageBox.critical(self, "Error", "No master password set")
            return

        self._app.start_crypto("decrypt", processed, self._state.master_password)

    def handle_decrypted(self, result: SecureString) -> None:
        try:
            text = result.get()
            self._decrypted_display.setText(text)
            self._verify_checksum.setText(f"Checksum: {MnemonicManager.checksum(text)}")
        finally:
            result.clear()

    def _start_camera(self) -> None:
        if not self._state.camera_available or self._camera_thread:
            return

        self._camera_status.setText("Initialising camera…")
        assert self._camera_start_btn is not None and self._camera_stop_btn is not None
        self._camera_start_btn.setEnabled(False)
        self._camera_stop_btn.setEnabled(True)

        worker = CameraWorker(self._config, self._camera_config)
        thread = QThread()
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.frame_captured.connect(self._on_camera_frame)
        worker.decoded.connect(self._on_camera_decoded)
        worker.status.connect(self._on_camera_status)
        worker.finished.connect(self._on_camera_finished)
        thread.finished.connect(thread.deleteLater)

        self._camera_thread = thread
        self._camera_worker = worker
        thread.start()

    def _stop_camera(self) -> None:
        if self._camera_worker:
            self._camera_worker.stop()
        if self._camera_thread and self._camera_thread.isRunning():
            self._camera_thread.quit()
            self._camera_thread.wait(1500)
        self._camera_thread = None
        self._camera_worker = None

        if self._camera_display:
            self._camera_display.clear()
            self._camera_display.setText("Camera preview will appear here")

        if self._camera_start_btn and self._camera_stop_btn:
            self._camera_start_btn.setEnabled(True)
            self._camera_stop_btn.setEnabled(False)

        if self._camera_status and "QR detected" not in self._camera_status.text():
            self._camera_status.setText("Camera stopped")

    def _on_camera_frame(self, frame) -> None:
        if not self._camera_display or self._cv2_module is None:
            return

        rgb = self._cv2_module.cvtColor(frame, self._cv2_module.COLOR_BGR2RGB)
        height, width, channel = rgb.shape
        image = QImage(rgb.data, width, height, channel * width, QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(image.copy())
        target_size = self._camera_display.size()
        if target_size.width() and target_size.height():
            pixmap = pixmap.scaled(target_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self._camera_display.setPixmap(pixmap)

    def _on_camera_decoded(self, payload: bytes) -> None:
        if self._camera_status:
            self._camera_status.setText("QR detected – decrypting…")
        self._stop_camera()
        self._process_loaded_data(payload, "Scanned from Camera")

    def _on_camera_status(self, message: str) -> None:
        if self._camera_status:
            self._camera_status.setText(message)

    def _on_camera_finished(self) -> None:
        if self._camera_thread and self._camera_thread.isRunning():
            self._camera_thread.quit()
            self._camera_thread.wait(1500)
        self._camera_thread = None
        self._camera_worker = None

        if self._camera_start_btn and self._camera_stop_btn:
            self._camera_start_btn.setEnabled(True)
            self._camera_stop_btn.setEnabled(False)

        if self._camera_status and self._camera_status.text() == "Initialising camera…":
            self._camera_status.setText("Camera unavailable")

    def stop_camera(self) -> None:
        self._stop_camera()


class SecureQRApp(QMainWindow):  # pragma: no cover - requires Qt event loop
    def __init__(self) -> None:
        super().__init__()

        self._config = AppConfig()
        self._camera_config = CameraConfig()
        self._style = StyleConfig()
        self._state = AppState()

        self._crypto_thread: QThread | None = None
        self._crypto_worker: CryptoWorker | None = None
        self._main_window: MainWindow | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        self.setWindowTitle(f"{self._config.app_name} v{self._config.app_version}")
        self.setGeometry(100, 100, 850, 750)
        self.setMinimumSize(700, 650)

        try:
            self.setWindowIcon(create_icon())
        except RuntimeError:
            pass

        self._apply_stylesheet()

        self._stack = QStackedWidget()
        self._lock_screen = LockScreen(self._config, self._style)
        self._lock_screen.unlocked.connect(self._on_unlocked)
        self._stack.addWidget(self._lock_screen)
        self.setCentralWidget(self._stack)

        self.show()

    def _apply_stylesheet(self) -> None:
        style = self._style
        self.setStyleSheet(
            f"""
            QMainWindow {{ background: {style.bg_primary}; }}
            QWidget {{ color: {style.fg_primary}; font-family: {style.font_family}; font-size: {style.font_size}px; }}
            QTabWidget::pane {{ border: none; }}
            QTabBar::tab {{ background: {style.bg_secondary}; padding: 12px 20px; border: 1px solid {style.border}; border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; }}
            QTabBar::tab:selected {{ background: {style.bg_tertiary}; color: {style.fg_secondary}; }}
            QGroupBox {{ font-weight: bold; border: 1px solid {style.border}; border-radius: 8px; margin-top: 1ex; padding: 15px; background: {style.bg_secondary}; }}
            QLineEdit, QTextEdit {{ background: {style.bg_primary}; color: {style.fg_secondary}; border: 1px solid {style.border}; border-radius: 4px; padding: 10px; }}
            QLineEdit:focus, QTextEdit:focus {{ border: 1px solid {style.accent_primary}; }}
            QPushButton {{ background: {style.accent_secondary}; color: {style.fg_secondary}; border: none; padding: 12px 18px; border-radius: 4px; font-weight: bold; }}
            QPushButton#AccentButton {{ background: {style.accent_primary}; color: {style.bg_primary}; }}
            QPushButton:hover {{ background: #81A1C1; }}
            #HeaderLabel {{ font-size: 24px; font-weight: bold; color: {style.fg_secondary}; }}
            #SubtleLabel {{ color: #81A1C1; }}
            #WarningLabel {{ background: {style.warning}; color: {style.bg_primary}; padding: 8px; border-radius: 4px; }}
            #SuccessLabel {{ background: {style.success}; color: {style.bg_primary}; padding: 8px; border-radius: 4px; }}
            #ChecksumLabel {{ font-family: {style.font_mono}; font-size: 16px; color: #EBCB8B; font-weight: bold; }}
            #CentralPanel {{ background: {style.bg_tertiary}; border-radius: 8px; padding: 20px; }}
            #qrDisplayLabel {{ border: 2px dashed {style.border}; background: {style.bg_primary}; border-radius: 4px; }}
            """
        )

    def _on_unlocked(self, password: SecureString) -> None:
        self._state.master_password = password
        self._main_window = MainWindow(
            self,
            self._config,
            self._state,
            self._style,
            self._camera_config,
        )
        self._stack.addWidget(self._main_window)
        self._stack.setCurrentWidget(self._main_window)
        self.resize(850, 850)

    def start_crypto(self, mode: str, data: Any, password: SecureString) -> None:
        self.stop_crypto()
        if self._main_window:
            self._main_window.setEnabled(False)

        thread = QThread()
        worker = CryptoWorker(CryptoManager(self._config), mode, data, password)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.finished.connect(self._on_crypto_finished)
        worker.error.connect(self._on_crypto_error)
        thread.finished.connect(thread.deleteLater)
        self._crypto_thread = thread
        self._crypto_worker = worker
        thread.start()

    def _on_crypto_finished(self, result: object) -> None:
        try:
            if not self._crypto_worker:
                return

            if self._crypto_worker._mode == "encrypt":
                assert isinstance(self._main_window, MainWindow)
                self._main_window.handle_encrypted(result)  # type: ignore[arg-type]
            else:
                assert isinstance(self._main_window, MainWindow)
                assert isinstance(result, SecureString)
                self._main_window.handle_decrypted(result)
        finally:
            self.stop_crypto()

    def _on_crypto_error(self, message: str) -> None:
        QMessageBox.critical(self, "Crypto Error", message)
        self.stop_crypto()

    def stop_crypto(self) -> None:
        if self._main_window:
            self._main_window.setEnabled(True)

        if self._crypto_thread and self._crypto_thread.isRunning():
            self._crypto_thread.quit()
            if not self._crypto_thread.wait(2000):
                self._crypto_thread.terminate()
                self._crypto_thread.wait()
        self._crypto_thread = None
        self._crypto_worker = None

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.stop_crypto()
        if self._main_window:
            self._main_window.stop_camera()
        if self._state.master_password:
            self._state.master_password.clear()
        self._state.master_password = None
        self._state.current_encrypted_payload = None
        self._state.current_encrypted_payload_bytes = None
        event.accept()


def run() -> int:  # pragma: no cover - requires Qt event loop
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("Secure QR Code Tool")
    window = SecureQRApp()
    return app.exec_()


__all__ = ["run", "SecureQRApp"]
