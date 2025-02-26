# QuantumNotes

Welcome to **QuantumNotes**, a standout note-taking application that combines cutting-edge encryption, an elegant graphical interface, and a seamless user experience. Unlike typical note apps, QuantumNotes offers a unique blend of security, aesthetics, and functionality—powered by a custom Feistel cipher with SHA-256, a PyQt5-driven interface inspired by the golden ratio, and advanced features like entropy-based password validation and versatile import/export options. Designed for privacy-conscious users and tech enthusiasts alike, it redefines secure note-taking.

## Latest Release: QuantumNotes v1.0.0 - First Release

**Released by**: [@SamuelSilvass](https://github.com/SamuelSilvass)  
**Date**: February 25, 2025 (latest as of this update)  
**Commit Hash**: `1047627`  
**Assets**:  
- `QuantumNotesInstaller.exe` (36.9 MB)  
- Source code (zip)  
- Source code (tar.gz)  

This is the inaugural release of QuantumNotes, marking its debut as a fully functional encrypted notes app built in Python with PyQt5.

### What's New in v1.0.0
- Initial stable version with core functionalities.
- Released with 3 commits to the `main` branch.

## Main Features

What sets QuantumNotes apart:

- **Unmatched Security**: Employs a custom Feistel cipher with 16 subkeys derived from your master password via SHA-256, offering encryption that’s both robust and tailored—unlike generic solutions used by mainstream apps.
- **Elegant Note Management**: Create, edit, save, and delete notes with rich text formatting (bold, italic, underline), all within a visually harmonious interface designed using the golden ratio and Fibonacci sequence for a uniquely pleasing experience.
- **Sophisticated Interface**: Built with PyQt5, featuring a sleek toolbar, an interactive note list, and a rich text editor—elevating note-taking beyond basic functionality into a modern, intuitive workflow.
- **Dynamic Themes**: Switch between light and dark modes with gradient designs inspired by mathematical beauty, providing a customizable look that’s rare in note-taking tools.
- **Versatile Import/Export**: Supports encrypted (`.qnt`), plain text (`.txt`), and compressed (`.zip`/`.rar`) formats, giving you flexible control over your data—ideal for backups or sharing securely.
- **Smart Authentication**: Requires a master password with real-time entropy analysis, rejecting weak passwords (entropy < 20) to ensure your notes stay protected, a feature not commonly found in similar apps.
- **Effortless Auto-Save**: Saves your work every 30 seconds, preventing data loss without interrupting your flow—a subtle but critical advantage.
- **Transparent Logging**: Tracks activities in a hidden log file (`~/.quantum_notes/quantum_notes.log`), offering insight for debugging or monitoring—an uncommon level of transparency for power users.

## Requirements

To run QuantumNotes, you will need the following dependencies:

- **Python 3.7+**
- **Python Libraries**:
  - `PyQt5` (graphical interface)
  - `pickle` (data serialization)
  - `hashlib` (encryption)
  - `configparser` (configuration management)
  - `shutil` (file operations)
  - `zipfile` (compressed file support)
  - `pathlib` (path handling)

Install the dependencies with:
```bash
pip install PyQt5
