# QuantumNotes

Welcome to **QuantumNotes**, a secure note-taking application with custom encryption, a modern graphical interface, and advanced features. This project was designed to provide an intuitive writing experience, supporting themes, text formatting, note import/export, and encryption based on a Feistel cipher using the `hashlib` library.

## Main Features

- **Secure Encryption**: Uses a custom Feistel cipher implementation with subkeys derived from a master password via SHA-256.
- **Note Management**: Create, edit, save, and delete notes with support for text formatting (bold, italic, underline).
- **Graphical Interface**: Built with PyQt5, featuring a toolbar, note list, and rich text editor.
- **Themes**: Toggle between light and dark themes with gradients inspired by the golden ratio.
- **Import and Export**: Supports encrypted notes (`.qnt`), plain text (`.txt`), and compressed files (`.zip`/`.rar`).
- **Authentication**: Login with a master password, including entropy analysis for security.
- **Auto-Save**: Automatically saves notes every 30 seconds.
- **Logging**: Activities are logged in a hidden file for monitoring and debugging.

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
