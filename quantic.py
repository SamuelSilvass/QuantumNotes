import sys
import os
import pickle
import zipfile
import configparser
import shutil
import hashlib
import math
from datetime import datetime
import logging
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QTextEdit,
                            QToolBar, QAction, QInputDialog, QMessageBox, QDialog, QVBoxLayout,
                            QLabel, QPushButton, QDockWidget, QFileDialog, QDialogButtonBox, QLineEdit,
                            QComboBox, QProgressBar, QWidget, QStatusBar, QShortcut, QHBoxLayout)
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect, QTimer
from PyQt5.QtGui import QFont, QColor, QLinearGradient, QBrush, QPalette, QClipboard, QKeySequence, QTextCharFormat

# Golden ratio constant
PHI = (1 + math.sqrt(5)) / 2  # ≈ 1.618
# Fibonacci sequence for spacing and sizing
FIBONACCI = [1, 1, 2, 3, 5, 8, 13, 21]

# Configure internal logging in a hidden directory
log_dir = Path.home() / ".quantum_notes"  # Exemplo: C:\Users\Muka & Bea\.quantum_notes
os.makedirs(log_dir, exist_ok=True)
log_file = log_dir / "quantum_notes.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('QuantumNotes')

class QuantumCypher:
    def __init__(self, password: str):
        self.password = password

    def derive_subkeys(self, num_keys=16):
        subkeys = []
        for i in range(num_keys):
            hash_input = self.password.encode() + i.to_bytes(4, 'big')
            subkey = hashlib.sha256(hash_input).digest()
            subkeys.append(subkey)
        return subkeys

    def feistel_encrypt(self, block: bytes, subkeys):
        L, R = block[:32], block[32:]
        for subkey in subkeys:
            F = hashlib.sha256(subkey + R).digest()[:32]
            new_R = bytes(a ^ b for a, b in zip(L, F))
            L = R
            R = new_R
        return R + L

    def feistel_decrypt(self, block: bytes, subkeys):
        R16, L16 = block[:32], block[32:]
        for subkey in reversed(subkeys):
            F = hashlib.sha256(subkey + L16).digest()[:32]
            new_L16 = bytes(a ^ b for a, b in zip(R16, F))
            R16 = L16
            L16 = new_L16
        return L16 + R16

    def encrypt_message(self, message: bytes, subkeys):
        block_size = 64
        blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]
        if len(blocks[-1]) < block_size:
            blocks[-1] = blocks[-1].ljust(block_size, b'\0')
        ciphertext = b''
        for block in blocks:
            ciphertext += self.feistel_encrypt(block, subkeys)
        return ciphertext

    def decrypt_message(self, ciphertext: bytes, subkeys):
        block_size = 64
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        message = b''
        for block in blocks:
            message += self.feistel_decrypt(block, subkeys)
        return message

    def encrypt(self, plaintext: str) -> bytes:
        if isinstance(plaintext, bytes):
            plaintext_bytes = plaintext
        else:
            plaintext_bytes = plaintext.encode('utf-8')
        length = len(plaintext_bytes)
        length_bytes = length.to_bytes(8, 'big')
        message = length_bytes + plaintext_bytes
        subkeys = self.derive_subkeys()
        ciphertext = self.encrypt_message(message, subkeys)
        return pickle.dumps(ciphertext)

    def decrypt(self, ciphertext: bytes) -> str:
        try:
            cipher_data = pickle.loads(ciphertext)
            if not isinstance(cipher_data, bytes):
                raise ValueError("Invalid encrypted data")
            subkeys = self.derive_subkeys()
            message = self.decrypt_message(cipher_data, subkeys)
            length = int.from_bytes(message[:8], 'big')
            plaintext_bytes = message[8:8+length]
            return plaintext_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")

    @staticmethod
    def calculate_entropy(password: str) -> float:
        length = len(password)
        if length == 0:
            return 0
        freq = {}
        for char in password:
            freq[char] = freq.get(char, 0) + 1
        entropy = -sum((f / length) * math.log2(f / length) for f in freq.values())
        return entropy * length

class FileManager:
    def __init__(self, cypher: QuantumCypher, notes_dir: str = "notes"):
        self.cypher = cypher
        self.notes_dir = notes_dir
        os.makedirs(self.notes_dir, exist_ok=True)

    def save_note(self, note_name: str, plaintext: str):
        try:
            encrypted = self.cypher.encrypt(plaintext)
            file_path = os.path.join(self.notes_dir, f"{note_name}.qnt")
            with open(file_path, "wb") as f:
                f.write(encrypted)
            logger.info(f"Note '{note_name}' saved")
            return os.path.getmtime(file_path)
        except Exception as e:
            logger.error(f"Failed to save note '{note_name}': {str(e)}")
            raise Exception(f"Error saving note: {str(e)}")

    def load_note(self, note_name: str) -> str:
        file_path = os.path.join(self.notes_dir, f"{note_name}.qnt")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                encrypted = f.read()
            return self.cypher.decrypt(encrypted)
        logger.warning(f"Note '{note_name}' not found")
        raise FileNotFoundError(f"Note '{note_name}' not found")

    def list_notes(self) -> list:
        return [f[:-4] for f in os.listdir(self.notes_dir) if f.endswith(".qnt")]

    def delete_note(self, note_name: str):
        file_path = os.path.join(self.notes_dir, f"{note_name}.qnt")
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Note '{note_name}' deleted")

    def export_note(self, note_name: str, mode: str, path: str):
        plaintext = self.load_note(note_name)
        try:
            if mode == "Encrypted":
                encrypted = self.cypher.encrypt(plaintext)
                with open(path, "wb") as f:
                    f.write(encrypted)
            elif mode == "Decrypted":
                with open(path, "w", encoding='utf-8') as f:
                    f.write(plaintext)
            elif mode == "Both":
                encrypted = self.cypher.encrypt(plaintext)
                with zipfile.ZipFile(path, "w") as zf:
                    zf.writestr(f"{note_name}.qnt", encrypted)
                    zf.writestr(f"{note_name}.txt", plaintext)
            logger.info(f"Note '{note_name}' exported as {mode}")
        except Exception as e:
            logger.error(f"Failed to export note '{note_name}': {str(e)}")
            raise Exception(f"Error exporting note: {str(e)}")

    def import_note(self, file_path: str, note_name: str):
        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext == ".qnt":
                with open(file_path, "rb") as f:
                    encrypted = f.read()
                plaintext = self.cypher.decrypt(encrypted)
                self.save_note(note_name, plaintext)
            elif ext == ".txt":
                with open(file_path, "r", encoding='utf-8') as f:
                    plaintext = f.read()
                self.save_note(note_name, plaintext)
            elif ext in [".zip", ".rar"]:
                with zipfile.ZipFile(file_path, "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".qnt"):
                            encrypted = zf.read(name)
                            plaintext = self.cypher.decrypt(encrypted)
                            self.save_note(note_name, plaintext)
                            break
                        elif name.endswith(".txt"):
                            plaintext = zf.read(name).decode('utf-8')
                            self.save_note(note_name, plaintext)
                            break
            else:
                raise Exception("Unsupported file format!")
            logger.info(f"Note imported as '{note_name}'")
            return True
        except Exception as e:
            logger.error(f"Failed to import note: {str(e)}")
            raise Exception(f"Error importing note: {str(e)}")

    def clear_all(self):
        if os.path.exists(self.notes_dir):
            shutil.rmtree(self.notes_dir)
        os.makedirs(self.notes_dir, exist_ok=True)
        logger.info("All notes have been cleared")

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumNotes - Secure Access")
        self.setFixedSize(int(400 * PHI), int(500 * PHI / 2))  # Smaller, yet harmonious with the golden ratio
        self.config = configparser.ConfigParser()
        self.config_file = "config.ini"
        self.is_first_use = not os.path.exists(self.config_file)
        self.cypher = None
        self.init_ui()
        self.apply_animations()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(int(FIBONACCI[4] * PHI))  # Rounded (8 * 1.618 ≈ 12.944 → 13)

        # Background with a scientifically inspired gradient, reflecting Da Vinci's optics
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #0a1421, stop:0.1618 #1a2d3f, stop:0.382 #2d4a6d, 
                    stop:0.618 #3a5f8a, stop:0.809 #4d7ca6, stop:1 #659ec3);
                border-radius: """ + str(int(FIBONACCI[3] * PHI)) + """;  # Rounded (3 * 1.618 ≈ 4.854 → 5)
                padding: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
            }
        """)

        # Centered title with a gradient based on mathematical ratios
        self.title = QLabel("QuantumNotes" if self.is_first_use else "Secure Access")
        self.title.setFont(QFont("Orbitron", int(28 * PHI / 2), QFont.Bold))  # Reduced size, yet proportional
        title_gradient = QLinearGradient(0, 0, 150 * PHI, 0)
        title_gradient.setColorAt(0, QColor("#e0f6ff"))  # Pure white light
        title_gradient.setColorAt(0.1618, QColor("#a2d9ff"))  # Clear sky (φ/10)
        title_gradient.setColorAt(0.382, QColor("#4d8cff"))  # Deep blue (φ/2.618)
        title_gradient.setColorAt(0.618, QColor("#8a2be2"))  # Mystic violet (φ)
        title_gradient.setColorAt(0.809, QColor("#ff00ff"))  # Vibrant magenta (φ + φ/2)
        title_gradient.setColorAt(1, QColor("#c400a2"))  # Rich shadow (φ^2)
        palette = self.title.palette()
        palette.setBrush(QPalette.WindowText, QBrush(title_gradient))
        self.title.setPalette(palette)
        self.title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.title)

        # Elliptical central container for inputs, with mathematical proportions
        input_container = QWidget()
        input_container_layout = QVBoxLayout()
        input_container_layout.setSpacing(int(FIBONACCI[3] * PHI))  # Rounded (3 * 1.618 ≈ 4.854 → 5)
        input_container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 rgba(255, 255, 255, 10), stop:0.618 rgba(255, 255, 255, 20), stop:1 rgba(255, 255, 255, 10));
                border-radius: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
                padding: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
                border: 2px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #00d4ff, stop:0.618 #ff00ff, stop:1 #8a2be2);
            }
        """)

        # Password field with geometric proportions
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Master Password")
        self.password_input.setFont(QFont("Roboto", int(16 * PHI / 2)))
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 15);
                color: #ffffff;
                border: 2px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #00d4ff, stop:0.618 #ff00ff, stop:1 #8a2be2);
                border-radius: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
                padding: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
                font: 16px 'Roboto';
            }
            QLineEdit:focus {
                border: 3px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #ff00ff, stop:0.618 #00d4ff, stop:1 #8a2be2);
            }
        """)

        input_container_layout.addWidget(self.password_input)

        # Confirmation field (first use)
        if self.is_first_use:
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Confirm Password")
            self.confirm_input.setFont(QFont("Roboto", int(16 * PHI / 2)))
            self.confirm_input.setStyleSheet("""
                QLineEdit {
                    background-color: rgba(255, 255, 255, 15);
                    color: #ffffff;
                    border: 2px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                        stop:0 #00d4ff, stop:0.618 #ff00ff, stop:1 #8a2be2);
                    border-radius: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
                    padding: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
                    font: 16px 'Roboto';
                }
                QLineEdit:focus {
                    border: 3px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                        stop:0 #ff00ff, stop:0.618 #00d4ff, stop:1 #8a2be2);
                }
            """)
            input_container_layout.addWidget(self.confirm_input)

        # Password strength bar with mathematical progression
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(int(15 * PHI / 2))
        self.strength_bar.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 8);
                border: 1px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #00d4ff, stop:0.618 #ff00ff, stop:1 #8a2be2);
                border-radius: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #00d4ff, stop:0.1618 #1e90ff, stop:0.382 #4d8cff, 
                    stop:0.618 #8a2be2, stop:0.809 #ff00ff, stop:1 #c400a2);
                border-radius: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
            }
        """)

        input_container_layout.addWidget(self.strength_bar)
        self.password_input.textChanged.connect(self.update_strength)

        input_container.setLayout(input_container_layout)
        main_layout.addWidget(input_container, alignment=Qt.AlignCenter)

        # Buttons with horizontal layout, based on mathematical proportions
        button_layout = QHBoxLayout()
        button_layout.setSpacing(int(FIBONACCI[3] * PHI))  # Rounded (3 * 1.618 ≈ 4.854 → 5)

        self.login_button = QPushButton("Start" if self.is_first_use else "Login")
        self.login_button.setFixedHeight(int(50 * PHI / 2))
        self.login_button.clicked.connect(self.accept)
        self.login_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #00d4ff, stop:0.1618 #1e90ff, stop:0.382 #4d8cff, 
                    stop:0.618 #8a2be2, stop:0.809 #ff00ff, stop:1 #c400a2);
                color: white;
                border-radius: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
                font: bold 18px 'Roboto';
                padding: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
                min-width: 120px;
            }
            QPushButton:hover {
                border: 3px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #ff00ff, stop:0.618 #00d4ff, stop:1 #8a2be2);
            }
        """)

        button_layout.addWidget(self.login_button)

        if not self.is_first_use:
            self.reset_button = QPushButton("Reset All")
            self.reset_button.setFixedHeight(int(45 * PHI / 2))
            self.reset_button.clicked.connect(self.reset_all)
            self.reset_button.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                        stop:0 #ff5555, stop:0.1618 #ff7777, stop:0.382 #ff9999, 
                        stop:0.618 #ffbbbb, stop:0.809 #ffdddd, stop:1 #ffeeee);
                    color: white;
                    border-radius: """ + str(int(FIBONACCI[2] * PHI)) + """;  # Rounded (2 * 1.618 ≈ 3.236 → 3)
                    font: bold 16px 'Roboto';
                    padding: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
                    min-width: 120px;
                }
                QPushButton:hover {
                    border: 3px solid qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                        stop:0 #ff5555, stop:0.618 #ff9999, stop:1 #ffdddd);
                }
            """)
            button_layout.addWidget(self.reset_button)

        main_layout.addLayout(button_layout)

        # Minimalist footer with scientific proportions
        footer = QWidget()
        footer.setFixedHeight(int(FIBONACCI[3] * PHI))  # Rounded (3 * 1.618 ≈ 4.854 → 5)
        footer.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #2d4a6d, stop:0.382 #3a5f8a, stop:0.618 #4d7ca6, stop:1 #659ec3);
                border-radius: """ + str(int(FIBONACCI[1] * PHI)) + """;  # Rounded (1 * 1.618 ≈ 1.618 → 2)
            }
        """)

        main_layout.addWidget(footer)

        self.setLayout(main_layout)

    def apply_animations(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(int(618))  # Approximately φ * 382 for harmony
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)  # Natural fluidity
        self.anim.start()

        # Scale animation for buttons, with natural curves
        for button in [self.login_button, self.reset_button] if not self.is_first_use else [self.login_button]:
            button_scale = QPropertyAnimation(button, b"geometry")
            button_scale.setDuration(int(500 * PHI / 2))  # Duration based on φ (rounded to 404)
            start_rect = QRect(button.geometry().x(), button.geometry().y(), button.width(), button.height())
            end_rect = QRect(button.geometry().x(), button.geometry().y(), int(button.width() * 1.05), int(button.height() * 1.05))
            button_scale.setStartValue(start_rect)
            button_scale.setEndValue(end_rect)
            button_scale.setEasingCurve(QEasingCurve.InOutQuad)  # Quadratic curve for natural movement
            button_scale.start()

    def update_strength(self):
        password = self.password_input.text()
        entropy = QuantumCypher.calculate_entropy(password)
        strength = min(int(entropy * 2), 100)
        self.strength_bar.setValue(strength)

    def get_password(self):
        return self.password_input.text().strip()

    def save_password(self, password):
        self.config['DEFAULT'] = {'password': self.cypher.encrypt(password).hex()}
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
        logger.info("Master password saved")

    def load_password(self):
        self.config.read(self.config_file)
        encrypted_pass_str = self.config['DEFAULT'].get('password', '')
        if not encrypted_pass_str:
            logger.error("No password found")
            raise ValueError("No saved password")
        try:
            encrypted_pass = bytes.fromhex(encrypted_pass_str)
            return self.cypher.decrypt(encrypted_pass)
        except Exception as e:
            logger.error(f"Error loading password: {str(e)}")
            raise Exception(f"Error loading password: {str(e)}")

    def reset_all(self):
        reply = QMessageBox.warning(self, "Reset All",
                                   "This will delete all notes and the current password.\nDo you want to continue?",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            new_password, ok = QInputDialog.getText(self, "New Password", "Enter the new password:", QLineEdit.Password)
            if ok and new_password:
                entropy = QuantumCypher.calculate_entropy(new_password)
                if entropy < 20:
                    QMessageBox.warning(self, "Warning", f"Weak password (entropy: {entropy:.1f}).\nUse a stronger password!")
                    logger.warning(f"Reset attempt with weak password (entropy: {entropy:.1f})")
                    return
                self.cypher = QuantumCypher(new_password)
                self.save_password(new_password)
                file_manager = FileManager(self.cypher)
                file_manager.clear_all()
                QMessageBox.information(self, "Success", "Everything has been reset! Use the new password to log in.")
                logger.info("System reset")
                self.password_input.clear()

    def validate_login(self):
        password = self.get_password()
        if not password:
            QMessageBox.warning(self, "Error", "Enter a password!")
            logger.warning("Login attempt without password")
            return False

        if self.is_first_use:
            if not hasattr(self, 'confirm_input') or password != self.confirm_input.text().strip():
                QMessageBox.warning(self, "Error", "Passwords do not match!")
                logger.warning("Passwords do not match on first use")
                return False
            entropy = QuantumCypher.calculate_entropy(password)
            if entropy < 20:
                QMessageBox.warning(self, "Warning", f"Weak password (entropy: {entropy:.1f}).\nUse a stronger password!")
                logger.warning(f"First use with weak password (entropy: {entropy:.1f})")
                return False
            self.cypher = QuantumCypher(password)
            self.save_password(password)
            file_manager = FileManager(self.cypher)
            file_manager.clear_all()
            logger.info("First login configured")
            return True
        else:
            self.cypher = QuantumCypher(password)
            try:
                saved_password = self.load_password()
                if password == saved_password:
                    logger.info("Login successful")
                    return True
                else:
                    QMessageBox.critical(self, "Error", "Incorrect password!")
                    logger.warning("Login attempt with incorrect password")
                    return False
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error validating password: {str(e)}")
                logger.error(f"Error validating login: {str(e)}")
                return False

class MainWindow(QMainWindow):
    def __init__(self, file_manager: FileManager):
        super().__init__()
        self.file_manager = file_manager
        self.current_note = None
        self.recent_notes = []
        self.is_dark_theme = True
        self.last_modified = None
        self.init_ui()

    def init_ui(self):
        width = 1200
        height = int(width / PHI) + int(150 * PHI)  # Increased to ensure full visibility, with extra margin
        self.setGeometry(100, 100, width, height)
        self.setWindowTitle("QuantumNotes")

        self.status_bar = QStatusBar()
        self.status_bar.setFixedHeight(int(20 * PHI / 2))
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Welcome to QuantumNotes")

        self.note_list = QTreeWidget()
        self.note_list.setHeaderLabels(["Notes"])
        self.note_list.itemClicked.connect(self.load_note)
        self.note_list.itemDoubleClicked.connect(self.view_note)
        self.dock = QDockWidget()
        self.dock.setWidget(self.note_list)
        self.dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.dock.setFixedWidth(int(width / PHI))  # Golden ratio for the dock
        self.addDockWidget(Qt.LeftDockWidgetArea, self.dock)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search notes...")
        self.search_bar.textChanged.connect(self.filter_notes)
        self.search_bar.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255, 255, 255, 50);
                color: #ffffff;
                border: 2px solid #00d4ff;
                border-radius: 12px;
                padding: 10px;
                font: 14px 'Roboto';
            }
            QLineEdit:focus {
                border: 3px solid #ff00ff;
            }
        """)
        self.dock.setTitleBarWidget(self.search_bar)

        editor_layout = QVBoxLayout()
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Roboto", int(16 * PHI / 2)))
        self.editor.setPlaceholderText("Start writing here...")
        self.editor.setAcceptRichText(True)
        self.editor.textChanged.connect(self.update_status)
        editor_layout.addWidget(self.editor)

        container = QWidget()
        container.setLayout(editor_layout)
        self.setCentralWidget(container)

        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setFixedHeight(int(50 * PHI))  # Adjusted height with golden ratio
        self.addToolBar(Qt.TopToolBarArea, self.toolbar)
        self.add_toolbar_actions()

        self.add_shortcuts()

        self.auto_save_timer = QTimer(self)
        self.auto_save_timer.timeout.connect(self.auto_save)
        self.auto_save_timer.start(30000)

        self.load_notes()
        self.apply_theme()
        self.add_animations()

    def add_toolbar_actions(self):
        actions = [
            ("✨ New", self.new_note),
            ("💾 Save", self.save_note),
            ("🔐 Encrypt", self.encrypt_text),
            ("🔓 Decrypt", self.decrypt_text),
            ("📤 Export", self.export_note),
            ("📥 Import", self.import_note),
            ("📋 Copy", self.copy_text),
            ("🗑️ Delete", self.delete_note),
            ("🌙 Theme", self.toggle_theme),
            ("B", self.make_bold),
            ("I", self.make_italic),
            ("U", self.make_underline),
        ]
        for name, callback in actions:
            action = QAction(name, self)
            action.triggered.connect(callback)
            self.toolbar.addAction(action)

    def add_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+S"), self, self.save_note)
        QShortcut(QKeySequence("Ctrl+N"), self, self.new_note)
        QShortcut(QKeySequence("Ctrl+D"), self, self.delete_note)
        QShortcut(QKeySequence("Ctrl+B"), self, self.make_bold)
        QShortcut(QKeySequence("Ctrl+I"), self, self.make_italic)
        QShortcut(QKeySequence("Ctrl+U"), self, self.make_underline)

    def apply_theme(self):
        if self.is_dark_theme:
            self.setStyleSheet("""
                QMainWindow {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e1e1e, stop:0.618 #2a2a2a);
                }
                QTreeWidget {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2a2a2a, stop:0.618 #333333);
                    color: #ffffff;
                    border: 2px solid #00d4ff;
                    border-radius: 12px;
                    padding: 15px;
                    font: 14px 'Roboto';
                }
                QTextEdit {
                    background-color: #ffffff;
                    border: 2px solid #00d4ff;
                    border-radius: 12px;
                    padding: 15px;
                    color: #333333;
                }
                QTextEdit:focus {
                    border: 3px solid #ff00ff;
                }
                QToolBar {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2a2a2a, stop:0.618 #333333);
                    padding: 5px;
                    border-radius: 12px;
                    margin: 2px;
                }
                QToolButton {
                    color: #ffffff;
                    font: 16px 'Roboto';
                    padding: 12px;
                    border-radius: 8px;
                }
                QToolButton:hover {
                    border: 2px solid #ff00ff;
                }
                QDockWidget {
                    background-color: transparent;
                }
                QStatusBar {
                    color: #aaaaaa;
                    font: 12px 'Roboto';
                }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #e0e0e0, stop:0.618 #f5f5f5);
                }
                QTreeWidget {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #f0f0f0, stop:0.618 #ffffff);
                    color: #333333;
                    border: 2px solid #00d4ff;
                    border-radius: 12px;
                    padding: 15px;
                    font: 14px 'Roboto';
                }
                QTextEdit {
                    background-color: #ffffff;
                    border: 2px solid #00d4ff;
                    border-radius: 12px;
                    padding: 15px;
                    color: #333333;
                }
                QTextEdit:focus {
                    border: 3px solid #ff00ff;
                }
                QToolBar {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #f0f0f0, stop:0.618 #ffffff);
                    padding: 5px;
                    border-radius: 12px;
                    margin: 2px;
                }
                QToolButton {
                    color: #333333;
                    font: 16px 'Roboto';
                    padding: 12px;
                    border-radius: 8px;
                }
                QToolButton:hover {
                    border: 2px solid #ff00ff;
                }
                QDockWidget {
                    background-color: transparent;
                }
                QStatusBar {
                    color: #666666;
                    font: 12px 'Roboto';
                }
            """)

    def add_animations(self):
        self.anim = QPropertyAnimation(self.editor, b"geometry")
        self.anim.setDuration(int(400 * PHI))  # Duration based on the golden ratio
        self.anim.setEasingCurve(QEasingCurve.OutCubic)  # Natural curve

    def animate_editor(self):
        start = self.editor.geometry()
        end = QRect(start.x(), start.y() - int(20 * PHI), start.width(), start.height() + int(40 * PHI))
        self.anim.setStartValue(start)
        self.anim.setEndValue(end)
        self.anim.start()
        QTimer.singleShot(int(200 * PHI), self.reset_animation)

    def reset_animation(self):
        start = self.editor.geometry()
        self.anim.setStartValue(start)
        self.anim.setEndValue(self.editor.geometry().adjusted(0, int(20 * PHI), 0, -int(40 * PHI)))
        self.anim.start()

    def load_notes(self):
        self.note_list.clear()
        try:
            for note in sorted(self.file_manager.list_notes()):
                item = QTreeWidgetItem([note])
                item.setFont(0, QFont("Roboto", int(14 * PHI / 2)))
                self.note_list.addTopLevelItem(item)
                if note not in self.recent_notes and len(self.recent_notes) < 5:
                    self.recent_notes.append(note)
            logger.debug("Notes loaded")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading notes: {str(e)}")
            logger.error(f"Error loading notes: {str(e)}")

    def filter_notes(self):
        search_text = self.search_bar.text().lower()
        for i in range(self.note_list.topLevelItemCount()):
            item = self.note_list.topLevelItem(i)
            item.setHidden(search_text not in item.text(0).lower())

    def new_note(self):
        note_name, ok = QInputDialog.getText(self, "New Note", "Note name:")
        if ok and note_name:
            if note_name in self.file_manager.list_notes():
                QMessageBox.warning(self, "Error", "Note already exists!")
                logger.warning(f"Attempt to create existing note: '{note_name}'")
                return
            self.editor.clear()
            self.current_note = note_name
            self.last_modified = None
            self.update_status()
            self.load_notes()
            self.animate_editor()
            logger.info(f"New note '{note_name}' created")

    def save_note(self):
        if not self.current_note:
            self.new_note()
            return
        try:
            plaintext = self.editor.toHtml()
            self.last_modified = self.file_manager.save_note(self.current_note, plaintext)
            self.load_notes()
            if self.current_note not in self.recent_notes and len(self.recent_notes) < 5:
                self.recent_notes.append(self.current_note)
            QMessageBox.information(self, "Success", "Note saved successfully!")
            self.animate_editor()
            self.update_status()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving: {str(e)}")
            logger.error(f"Error saving note '{self.current_note}': {str(e)}")

    def auto_save(self):
        if self.current_note and self.editor.toPlainText():
            try:
                plaintext = self.editor.toHtml()
                self.last_modified = self.file_manager.save_note(self.current_note, plaintext)
                self.status_bar.showMessage("Note autosaved", 2000)
                logger.debug(f"Note '{self.current_note}' autosaved")
            except Exception as e:
                self.status_bar.showMessage(f"Error autosaving: {str(e)}", 5000)
                logger.error(f"Error autosaving '{self.current_note}': {str(e)}")

    def load_note(self, item):
        try:
            note_name = item.text(0)
            plaintext = self.file_manager.load_note(note_name)
            self.editor.setHtml(plaintext)
            self.current_note = note_name
            file_path = os.path.join(self.file_manager.notes_dir, f"{note_name}.qnt")
            self.last_modified = os.path.getmtime(file_path)
            if note_name not in self.recent_notes and len(self.recent_notes) < 5:
                self.recent_notes.append(note_name)
            self.update_status()
            self.animate_editor()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading: {str(e)}")
            logger.error(f"Error loading note '{item.text(0)}': {str(e)}")

    def delete_note(self):
        if self.current_note:
            reply = QMessageBox.question(self, "Confirmation",
                                        f"Delete '{self.current_note}'?",
                                        QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    self.file_manager.delete_note(self.current_note)
                    self.editor.clear()
                    if self.current_note in self.recent_notes:
                        self.recent_notes.remove(self.current_note)
                    self.current_note = None
                    self.last_modified = None
                    self.update_status()
                    self.load_notes()
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Error deleting: {str(e)}")
                    logger.error(f"Error deleting note '{self.current_note}': {str(e)}")

    def encrypt_text(self):
        if self.current_note and self.editor.toPlainText():
            try:
                encrypted_bytes = self.file_manager.cypher.encrypt(self.editor.toHtml())
                encrypted_display = ''.join(chr(b % 127) for b in pickle.loads(encrypted_bytes)[:10]) + "..."
                dialog = NoteViewerDialog("Encrypted Note", encrypted_display, self.editor.toHtml(), self)
                dialog.exec_()
                logger.info(f"Note '{self.current_note}' encrypted for viewing")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error encrypting: {str(e)}")
                logger.error(f"Error encrypting note '{self.current_note}': {str(e)}")

    def decrypt_text(self):
        if self.current_note:
            try:
                plaintext = self.file_manager.load_note(self.current_note)
                file_path = os.path.join(self.file_manager.notes_dir, f"{self.current_note}.qnt")
                with open(file_path, "rb") as f:
                    encrypted_bytes = f.read()
                encrypted_display = ''.join(chr(b % 127) for b in pickle.loads(encrypted_bytes)[:10]) + "..."
                dialog = NoteViewerDialog("Decrypted Note", encrypted_display, plaintext, self)
                dialog.exec_()
                logger.info(f"Note '{self.current_note}' decrypted for viewing")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error decrypting: {str(e)}")
                logger.error(f"Error decrypting note '{self.current_note}': {str(e)}")

    def export_note(self):
        if not self.current_note:
            QMessageBox.warning(self, "Error", "No note selected!")
            logger.warning("Attempt to export without a selected note")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Export Note")
        dialog.setFixedSize(int(300 * PHI), int(300 * PHI))  # Adjusted for golden ratio
        layout = QVBoxLayout()

        label = QLabel("Choose export format:")
        layout.addWidget(label)

        combo = QComboBox()
        combo.addItems(["Encrypted", "Decrypted", "Both"])
        layout.addWidget(combo)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        dialog.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e1e1e, stop:0.618 #2a2a2a);
                border-radius: 15px;
                padding: 15px;
            }
            QLabel {
                color: #ffffff;
                font: 14px 'Roboto';
            }
            QComboBox {
                background-color: rgba(255, 255, 255, 50);
                color: #ffffff;
                border: 2px solid #00d4ff;
                border-radius: 10px;
                padding: 5px;
            }
            QComboBox:focus {
                border: 3px solid #ff00ff;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00d4ff, stop:1 #ff00ff);
                color: white;
                border-radius: 10px;
                font: bold 12px 'Roboto';
                padding: 10px;
            }
            QPushButton:hover {
                border: 2px solid #ff00ff;
            }
        """)
        if dialog.exec_() != QDialog.Accepted:
            return

        mode = combo.currentText()
        ext = ".qnt" if mode == "Encrypted" else ".txt" if mode == "Decrypted" else ".rar"
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Note",
                                                  f"{self.current_note}{ext}",
                                                  "Quantum Files (*.qnt);;Text Files (*.txt);;RAR Files (*.rar)")
        if file_path:
            try:
                self.file_manager.export_note(self.current_note, mode, file_path)
                QMessageBox.information(self, "Success", "Note exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error exporting: {str(e)}")

    def import_note(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Note", "",
                                                  "All Supported (*.qnt *.txt *.rar *.zip);;Quantum Files (*.qnt);;Text Files (*.txt);;RAR Files (*.rar);;ZIP Files (*.zip)")
        if not file_path:
            return

        note_name, ok = QInputDialog.getText(self, "Import Note", "Choose a name for the imported note:")
        if not (ok and note_name):
            return

        if note_name in self.file_manager.list_notes():
            QMessageBox.warning(self, "Error", "Note already exists!")
            logger.warning(f"Attempt to import note with existing name: '{note_name}'")
            return

        try:
            self.file_manager.import_note(file_path, note_name)
            self.load_notes()
            self.current_note = note_name
            self.editor.setHtml(self.file_manager.load_note(note_name))
            self.last_modified = os.path.getmtime(os.path.join(self.file_manager.notes_dir, f"{note_name}.qnt"))
            self.update_status()
            QMessageBox.information(self, "Success", "Note imported successfully!")
            self.animate_editor()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error importing: {str(e)}")

    def view_note(self, item):
        note_name = item.text(0)
        try:
            file_path = os.path.join(self.file_manager.notes_dir, f"{note_name}.qnt")
            with open(file_path, "rb") as f:
                encrypted_bytes = f.read()
            decrypted = self.file_manager.cypher.decrypt(encrypted_bytes)
            encrypted_display = ''.join(chr(b % 127) for b in pickle.loads(encrypted_bytes)[:10]) + "..."
            dialog = NoteViewerDialog(f"View: {note_name}", encrypted_display, decrypted, self)
            dialog.exec_()
            logger.info(f"Note '{note_name}' viewed")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error viewing: {str(e)}")
            logger.error(f"Error viewing note '{note_name}': {str(e)}")

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.apply_theme()
        logger.info(f"Theme changed to {'dark' if self.is_dark_theme else 'light'}")

    def update_status(self):
        text = self.editor.toPlainText()
        words = len(text.split())
        status = f"Words: {words}"
        if self.last_modified:
            mod_time = datetime.fromtimestamp(self.last_modified).strftime('%Y-%m-%d %H:%M:%S')
            status += f" | Last modified: {mod_time}"
        self.status_bar.showMessage(status)

    def copy_text(self):
        if self.editor.toPlainText():
            clipboard = QApplication.clipboard()
            clipboard.setText(self.editor.toPlainText())
            QMessageBox.information(self, "Success", "Text copied to clipboard!")
            logger.info(f"Text from note '{self.current_note}' copied")

    def make_bold(self):
        cursor = self.editor.textCursor()
        if cursor.hasSelection():
            fmt = QTextCharFormat()
            fmt.setFontWeight(QFont.Bold if cursor.charFormat().fontWeight() != QFont.Bold else QFont.Normal)
            cursor.mergeCharFormat(fmt)
        else:
            self.editor.setFontWeight(QFont.Bold if self.editor.fontWeight() != QFont.Bold else QFont.Normal)

    def make_italic(self):
        cursor = self.editor.textCursor()
        if cursor.hasSelection():
            fmt = QTextCharFormat()
            fmt.setFontItalic(not cursor.charFormat().fontItalic())
            cursor.mergeCharFormat(fmt)
        else:
            self.editor.setFontItalic(not self.editor.fontItalic())

    def make_underline(self):
        cursor = self.editor.textCursor()
        if cursor.hasSelection():
            fmt = QTextCharFormat()
            fmt.setFontUnderline(not cursor.charFormat().fontUnderline())
            cursor.mergeCharFormat(fmt)
        else:
            self.editor.setFontUnderline(not self.editor.fontUnderline())

class NoteViewerDialog(QDialog):
    def __init__(self, title, encrypted_text, decrypted_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(int(500 * PHI), int(500 * PHI))  # Adjusted for golden ratio
        layout = QVBoxLayout()

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Roboto", int(14 * PHI / 2)))
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                border: 2px solid #00d4ff;
                border-radius: 12px;
                padding: 15px;
                color: #333333;
            }
        """)
        layout.addWidget(self.text_edit)

        crypto_btn = QPushButton("View Encrypted")
        plain_btn = QPushButton("View Decrypted")
        crypto_btn.clicked.connect(lambda: self.text_edit.setText(encrypted_text))
        plain_btn.clicked.connect(lambda: self.text_edit.setHtml(decrypted_text))
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.addButton(crypto_btn, QDialogButtonBox.ActionRole)
        buttons.addButton(plain_btn, QDialogButtonBox.ActionRole)
        buttons.accepted.connect(self.accept)
        buttons.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00d4ff, stop:1 #ff00ff);
                color: white;
                border-radius: 10px;
                font: bold 12px 'Roboto';
                padding: 10px;
            }
            QPushButton:hover {
                border: 2px solid #ff00ff;
            }
        """)
        layout.addWidget(buttons)

        self.setLayout(layout)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e1e1e, stop:0.618 #2a2a2a);
                border-radius: 15px;
                padding: 15px;
            }
        """)
        self.text_edit.setHtml(decrypted_text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_dialog = LoginDialog()
    if login_dialog.is_first_use and os.path.exists(login_dialog.config_file):
        os.remove(login_dialog.config_file)
        login_dialog.is_first_use = True
    if login_dialog.exec_() == QDialog.Accepted and login_dialog.validate_login():
        cypher = login_dialog.cypher
        file_manager = FileManager(cypher)
        window = MainWindow(file_manager)
        window.show()
        logger.info("QuantumNotes application started")
        sys.exit(app.exec_())