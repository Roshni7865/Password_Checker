# 🔑 Password Strength Checker

A Python application to analyze and visualize the strength of passwords.  
Supports both **GUI (Tkinter)** and **Console mode**.

---

## 🚀 Features
- Detects common weak passwords.
- Calculates **password entropy** (measure of unpredictability).
- Analyzes:
  - Length
  - Uppercase / Lowercase letters
  - Numbers
  - Special characters
  - Unique characters
  - Repetition score
- Provides **strength rating**: Very Weak, Weak, Medium, Strong, Very Strong.
- Gives **real-time suggestions** to improve password security.
- **Tkinter GUI** with progress bar, details panel, and suggestions box.
- **Console version** for CLI users.

---

## 🖥️ GUI Preview
When run without arguments, the Tkinter GUI opens:  
- Enter your password in the input box.  
- View strength, entropy, and detailed analysis in real time.  
- Suggestions are displayed for improvement.  

---

## 📦 Requirements
- Python 3.7+
- Tkinter (comes pre-installed with Python)
- Standard libraries: `re`, `math`, `tkinter`, `json`, `os`, `typing`

No external dependencies required 🎉

---

## ⚡ Usage

### 1. Clone the repository
```bash
git clone https://github.com/your-username/password-strength-checker.git
cd password-strength-checker


2. **Run in GUI mode**
python password_strength_checker.py

##📜 License

This project is licensed under the MIT License.
