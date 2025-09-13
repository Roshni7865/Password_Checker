# password_strength_checker.py
import re
import math
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Tuple
import json
import os

class PasswordStrengthChecker:
    def __init__(self):
        # Common weak passwords list
        self.common_passwords = self.load_common_passwords()
        
    def load_common_passwords(self) -> List[str]:
        """Load a list of common weak passwords"""
        common_passwords = [
            'password', '123456', '12345678', '1234', 'qwerty', '12345', 
            'dragon', 'baseball', 'football', 'letmein', 'monkey', 'mustang',
            'michael', 'shadow', 'master', 'jennifer', '111111', '2000',
            'jordan', 'superman', 'harley', '1234567', 'freedom', 'matrix'
        ]
        return common_passwords

    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (measure of unpredictability)"""
        # Character pool size estimation
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'[0-9]', password):
            pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += 33  # Common special characters
            
        if pool_size == 0:
            return 0
            
        # Entropy formula: log2(pool_size^length)
        entropy = len(password) * math.log2(pool_size)
        return entropy

    def check_password_strength(self, password: str) -> Dict:
        """Comprehensive password strength analysis"""
        if not password:
            return {
                'score': 0,
                'strength': 'Very Weak',
                'suggestions': ['Please enter a password'],
                'details': {}
            }
            
        # Initialize result
        result = {
            'score': 0,
            'strength': 'Very Weak',
            'suggestions': [],
            'details': {
                'length': len(password),
                'has_upper': False,
                'has_lower': False,
                'has_digit': False,
                'has_special': False,
                'common_password': False,
                'entropy': 0,
                'unique_chars': len(set(password)),
                'repetition_score': 0
            }
        }
        
        # Check for common password
        if password.lower() in self.common_passwords:
            result['details']['common_password'] = True
            result['suggestions'].append('This is a very common password. Choose something more unique.')
        
        # Check character types
        if re.search(r'[A-Z]', password):
            result['details']['has_upper'] = True
            result['score'] += 1
            
        if re.search(r'[a-z]', password):
            result['details']['has_lower'] = True
            result['score'] += 1
            
        if re.search(r'[0-9]', password):
            result['details']['has_digit'] = True
            result['score'] += 1
            
        if re.search(r'[^a-zA-Z0-9]', password):
            result['details']['has_special'] = True
            result['score'] += 2  # Extra points for special chars
            
        # Length scoring
        if len(password) >= 8:
            result['score'] += 1
        if len(password) >= 12:
            result['score'] += 2
        if len(password) >= 16:
            result['score'] += 3
            
        # Entropy calculation
        entropy = self.calculate_entropy(password)
        result['details']['entropy'] = entropy
        
        # Entropy scoring
        if entropy > 60:
            result['score'] += 2
        elif entropy > 40:
            result['score'] += 1
            
        # Unique characters scoring
        uniqueness = len(set(password)) / len(password)
        result['details']['repetition_score'] = uniqueness * 100
        
        if uniqueness > 0.8:
            result['score'] += 1
        elif uniqueness < 0.5:
            result['score'] -= 1
            result['suggestions'].append('Too many repeated characters. Try using more diverse characters.')
        
        # Final strength assessment
        if result['score'] <= 3:
            result['strength'] = 'Very Weak'
            result['suggestions'].append('Add more character types (uppercase, lowercase, numbers, symbols)')
            result['suggestions'].append('Make the password longer (at least 12 characters)')
        elif result['score'] <= 5:
            result['strength'] = 'Weak'
            result['suggestions'].append('Add more character types')
            result['suggestions'].append('Increase length to at least 12 characters')
        elif result['score'] <= 7:
            result['strength'] = 'Medium'
            result['suggestions'].append('Add special characters for better security')
        elif result['score'] <= 9:
            result['strength'] = 'Strong'
        else:
            result['strength'] = 'Very Strong'
            
        # Ensure we have at least some suggestions
        if not result['suggestions'] and result['score'] < 10:
            result['suggestions'].append('Consider using a passphrase for even better security')
            
        return result

class PasswordCheckerGUI:
    def __init__(self):
        self.checker = PasswordStrengthChecker()
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("Password Strength Checker")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('Title.TLabel', background='#f0f0f0', font=('Arial', 14, 'bold'))
        self.style.configure('Strength.TLabel', font=('Arial', 12, 'bold'))
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        
        # Create widgets
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title = ttk.Label(self.main_frame, text="Password Strength Analyzer", style='Title.TLabel')
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password entry
        ttk.Label(self.main_frame, text="Enter Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.main_frame, textvariable=self.password_var, show='*', width=40)
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.password_var.trace('w', self.on_password_change)
        
        # Show password checkbox
        self.show_password_var = tk.IntVar()
        show_password_cb = ttk.Checkbutton(self.main_frame, text="Show password", 
                                          variable=self.show_password_var, 
                                          command=self.toggle_password_visibility)
        show_password_cb.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Strength indicator
        ttk.Label(self.main_frame, text="Strength:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.strength_label = ttk.Label(self.main_frame, text="Please enter a password", style='Strength.TLabel')
        self.strength_label.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Details frame
        details_frame = ttk.LabelFrame(self.main_frame, text="Password Details", padding="10")
        details_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        details_frame.columnconfigure(1, weight=1)
        
        # Detail labels
        self.detail_vars = {}
        details = [
            ('Length', 'length'),
            ('Uppercase Letters', 'has_upper'),
            ('Lowercase Letters', 'has_lower'),
            ('Digits', 'has_digit'),
            ('Special Characters', 'has_special'),
            ('Unique Characters', 'unique_chars'),
            ('Entropy', 'entropy'),
            ('Repetition Score', 'repetition_score'),
            ('Common Password', 'common_password')
        ]
        
        for i, (label, key) in enumerate(details):
            ttk.Label(details_frame, text=f"{label}:").grid(row=i, column=0, sticky=tk.W, pady=2)
            var = tk.StringVar(value="N/A")
            self.detail_vars[key] = var
            ttk.Label(details_frame, textvariable=var).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Suggestions frame
        suggestions_frame = ttk.LabelFrame(self.main_frame, text="Suggestions", padding="10")
        suggestions_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        suggestions_frame.columnconfigure(0, weight=1)
        suggestions_frame.rowconfigure(0, weight=1)
        
        # Suggestions text
        self.suggestions_text = tk.Text(suggestions_frame, height=4, width=50, wrap=tk.WORD)
        self.suggestions_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add scrollbar to suggestions
        scrollbar = ttk.Scrollbar(suggestions_frame, orient=tk.VERTICAL, command=self.suggestions_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.suggestions_text.configure(yscrollcommand=lambda f, l: scrollbar.set(f, l))
        
        # Button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        # Check button
        ttk.Button(button_frame, text="Check Password", command=self.check_password).grid(row=0, column=0, padx=5)
        
        # Clear button
        ttk.Button(button_frame, text="Clear", command=self.clear_fields).grid(row=0, column=1, padx=5)
        
        # Exit button
        ttk.Button(button_frame, text="Exit", command=self.root.quit).grid(row=0, column=2, padx=5)
        
    def toggle_password_visibility(self):
        if self.show_password_var.get() == 1:
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')
            
    def on_password_change(self, *args):
        # Update analysis in real-time as user types
        self.check_password()
        
    def check_password(self):
        password = self.password_var.get()
        result = self.checker.check_password_strength(password)
        
        # Update strength label and progress bar
        self.strength_label.config(text=result['strength'])
        
        # Set color based on strength
        colors = {
            'Very Weak': '#ff0000',
            'Weak': '#ff5252',
            'Medium': '#ffb142',
            'Strong': '#2ed573',
            'Very Strong': '#1e90ff'
        }
        self.strength_label.config(foreground=colors.get(result['strength'], 'black'))
        
        # Update progress bar
        score_percent = min(result['score'] * 10, 100)
        self.progress['value'] = score_percent
        
        # Update progress bar color
        if score_percent < 40:
            self.style.configure("Horizontal.TProgressbar", background='#ff0000')
        elif score_percent < 60:
            self.style.configure("Horizontal.TProgressbar", background='#ff5252')
        elif score_percent < 80:
            self.style.configure("Horizontal.TProgressbar", background='#ffb142')
        else:
            self.style.configure("Horizontal.TProgressbar", background='#2ed573')
        
        # Update details
        details = result['details']
        self.detail_vars['length'].set(details['length'])
        self.detail_vars['has_upper'].set('Yes' if details['has_upper'] else 'No')
        self.detail_vars['has_lower'].set('Yes' if details['has_lower'] else 'No')
        self.detail_vars['has_digit'].set('Yes' if details['has_digit'] else 'No')
        self.detail_vars['has_special'].set('Yes' if details['has_special'] else 'No')
        self.detail_vars['unique_chars'].set(details['unique_chars'])
        self.detail_vars['entropy'].set(f"{details['entropy']:.2f} bits")
        self.detail_vars['repetition_score'].set(f"{details['repetition_score']:.1f}%")
        self.detail_vars['common_password'].set('Yes' if details['common_password'] else 'No')
        
        # Update suggestions
        self.suggestions_text.delete(1.0, tk.END)
        if result['suggestions']:
            for suggestion in result['suggestions']:
                self.suggestions_text.insert(tk.END, f"• {suggestion}\n")
        else:
            self.suggestions_text.insert(tk.END, "Your password is excellent! No suggestions.")
            
    def clear_fields(self):
        self.password_var.set("")
        self.strength_label.config(text="Please enter a password", foreground='black')
        self.progress['value'] = 0
        for var in self.detail_vars.values():
            var.set("N/A")
        self.suggestions_text.delete(1.0, tk.END)
        
    def run(self):
        self.root.mainloop()

# Console version
def console_version():
    """Run the password checker in console mode"""
    checker = PasswordStrengthChecker()
    
    print("=== Password Strength Checker ===")
    print("Enter a password to check its strength (or 'quit' to exit):")
    
    while True:
        password = input("\nPassword: ")
        
        if password.lower() == 'quit':
            break
            
        result = checker.check_password_strength(password)
        
        print(f"\nStrength: {result['strength']} (Score: {result['score']}/10)")
        print(f"Length: {result['details']['length']}")
        print(f"Contains uppercase: {'Yes' if result['details']['has_upper'] else 'No'}")
        print(f"Contains lowercase: {'Yes' if result['details']['has_lower'] else 'No'}")
        print(f"Contains digits: {'Yes' if result['details']['has_digit'] else 'No'}")
        print(f"Contains special chars: {'Yes' if result['details']['has_special'] else 'No'}")
        print(f"Unique characters: {result['details']['unique_chars']}")
        print(f"Entropy: {result['details']['entropy']:.2f} bits")
        print(f"Repetition score: {result['details']['repetition_score']:.1f}%")
        print(f"Common password: {'Yes' if result['details']['common_password'] else 'No'}")
        
        if result['suggestions']:
            print("\nSuggestions for improvement:")
            for suggestion in result['suggestions']:
                print(f"- {suggestion}")
        else:
            print("\nYour password is excellent! No suggestions.")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--console":
        console_version()
    else:
        app = PasswordCheckerGUI()
        app.run() 
