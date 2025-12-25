import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import string
import json
import os
import re
import winsound
import time
import threading

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Modern Password Generator")
        self.root.geometry("700x750")
        self.root.resizable(True, True)
        self.root.configure(bg='white')

        # Style
        style = ttk.Style()
        style.configure("TLabel", font=("Arial", 10), background='white', foreground='black')
        style.configure("TButton", font=("Arial", 10), background='white', foreground='black')
        style.configure("TCheckbutton", font=("Arial", 10), background='white', foreground='black')
        style.configure("TFrame", background='white')
        style.configure("TLabelframe", background='white', foreground='black')
        style.configure("TLabelframe.Label", font=("Arial", 11, "bold"), background='white', foreground='black')
        style.configure("TEntry", fieldbackground='white', foreground='black', insertcolor='black')

        # Menu
        menubar = tk.Menu(root)
        root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Passwords", command=self.save_passwords)
        file_menu.add_command(label="Load Passwords", command=self.load_passwords)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)

        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear History", command=self.clear_history)
        tools_menu.add_command(label="Export as Text", command=self.export_as_text)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Creator", command=self.show_creator_info)
        help_menu.add_command(label="Terms & Conditions", command=self.show_terms_and_conditions)
        help_menu.add_command(label="Privacy Policy", command=self.show_privacy_policy)

        # Main frame
        main_frame = ttk.Frame(root, padding="5")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Modern Password Generator", font=("Arial", 18, "bold"))
        title_label.pack(pady=5)

        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="5")
        config_frame.pack(pady=5, fill=tk.X)

        # Length
        length_frame = ttk.Frame(config_frame)
        length_frame.pack(pady=2, fill=tk.X)
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT)
        self.length_var = tk.IntVar(value=12)
        self.length_spin = tk.Spinbox(length_frame, from_=4, to=128, textvariable=self.length_var, width=5, font=("Arial", 10), bg='white', fg='black', insertbackground='black')
        self.length_spin.pack(side=tk.RIGHT)

        # Character options
        char_frame = ttk.LabelFrame(config_frame, text="Character Types", padding="5")
        char_frame.pack(pady=5, fill=tk.X)

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(char_frame, text="Uppercase Letters (A-Z)", variable=self.upper_var, command=self.update_strength).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(char_frame, text="Lowercase Letters (a-z)", variable=self.lower_var, command=self.update_strength).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(char_frame, text="Digits (0-9)", variable=self.digits_var, command=self.update_strength).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(char_frame, text="Symbols (!@#$%^&*)", variable=self.symbols_var, command=self.update_strength).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(char_frame, text="Exclude Similar Characters (0OIl1)", variable=self.exclude_similar_var, command=self.update_strength).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)

        # Personalized options
        personal_frame = ttk.LabelFrame(config_frame, text="Personalized Generation", padding="5")
        personal_frame.pack(pady=5, fill=tk.X)

        ttk.Label(personal_frame, text="Enter Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.name_var = tk.StringVar()
        self.name_entry = ttk.Entry(personal_frame, textvariable=self.name_var, width=20, font=("Arial", 10))
        self.name_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        self.include_name_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(personal_frame, text="Include name in password", variable=self.include_name_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)

        # Generate button
        self.generate_button = tk.Button(main_frame, text="Generate Secure Password", command=self.generate_password, bg="#007BFF", fg="white", font=("Arial", 12, "bold"), relief="flat", bd=0, padx=20, pady=10, width=25)
        self.generate_button.pack(pady=5)
        self.generate_button.bind("<Enter>", lambda e: self.generate_button.config(bg="#0056b3"))
        self.generate_button.bind("<Leave>", lambda e: self.generate_button.config(bg="#007BFF"))

        # Output frame
        output_frame = ttk.LabelFrame(main_frame, text="Generated Password", padding="5")
        output_frame.pack(pady=5, fill=tk.X)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(output_frame, textvariable=self.password_var, font=("Arial", 12), state="readonly")
        self.password_entry.pack(fill=tk.X, pady=2)

        # Progress bar for generation
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(output_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=2)

        # Crack time label
        self.crack_time_var = tk.StringVar(value="Crack time: N/A")
        self.crack_time_label = ttk.Label(output_frame, textvariable=self.crack_time_var, font=("Arial", 10))
        self.crack_time_label.pack(pady=2)

        # Strength indicator
        strength_frame = ttk.Frame(output_frame)
        strength_frame.pack(fill=tk.X, pady=2)
        ttk.Label(strength_frame, text="Strength:").pack(side=tk.LEFT)
        self.strength_var = tk.StringVar(value="Weak")
        self.strength_label = ttk.Label(strength_frame, textvariable=self.strength_var, font=("Arial", 10, "bold"))
        self.strength_label.pack(side=tk.LEFT, padx=5)
        self.strength_bar = ttk.Progressbar(strength_frame, length=200, mode='determinate')
        self.strength_bar.pack(side=tk.RIGHT)

        # Buttons
        button_frame = ttk.Frame(output_frame)
        button_frame.pack(fill=tk.X, pady=2)
        self.copy_button = tk.Button(button_frame, text="Copy", command=self.copy_to_clipboard, bg="#28a745", fg="white", font=("Arial", 10, "bold"), relief="flat", bd=0, padx=15, pady=8)
        self.copy_button.pack(side=tk.LEFT, padx=10)
        self.copy_button.bind("<Enter>", lambda e: self.copy_button.config(bg="#218838"))
        self.copy_button.bind("<Leave>", lambda e: self.copy_button.config(bg="#28a745"))

        self.save_button = tk.Button(button_frame, text="Save", command=self.save_current_password, bg="#ffc107", fg="black", font=("Arial", 10, "bold"), relief="flat", bd=0, padx=15, pady=8)
        self.save_button.pack(side=tk.LEFT, padx=10)
        self.save_button.bind("<Enter>", lambda e: self.save_button.config(bg="#e0a800"))
        self.save_button.bind("<Leave>", lambda e: self.save_button.config(bg="#ffc107"))

        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_password, bg="#dc3545", fg="white", font=("Arial", 10, "bold"), relief="flat", bd=0, padx=15, pady=8)
        self.clear_button.pack(side=tk.LEFT, padx=10)
        self.clear_button.bind("<Enter>", lambda e: self.clear_button.config(bg="#c82333"))
        self.clear_button.bind("<Leave>", lambda e: self.clear_button.config(bg="#dc3545"))

        # History
        history_frame = ttk.LabelFrame(main_frame, text="Password History", padding="5")
        history_frame.pack(pady=5, fill=tk.BOTH, expand=True)

        self.history_listbox = tk.Listbox(history_frame, height=8, font=("Arial", 10), bg='white', fg='black', selectbackground='#007BFF', selectforeground='white')
        self.history_listbox.pack(fill=tk.BOTH, expand=True)
        self.history_listbox.bind('<Double-1>', self.copy_from_history)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Configure options and generate password")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.passwords = []
        self.update_strength()

    def update_strength(self):
        length = self.length_var.get()
        char_types = sum([self.upper_var.get(), self.lower_var.get(), self.digits_var.get(), self.symbols_var.get()])
        strength = 0
        if length >= 8:
            strength += 1
        if length >= 12:
            strength += 1
        if char_types >= 2:
            strength += 1
        if char_types >= 3:
            strength += 1
        if char_types >= 4:
            strength += 1
        if self.exclude_similar_var.get():
            strength += 0.5

        self.strength_bar['value'] = min(strength * 20, 100)
        if strength < 2:
            self.strength_var.set("Weak")
            self.strength_label.config(foreground="red")
        elif strength < 4:
            self.strength_var.set("Medium")
            self.strength_label.config(foreground="orange")
        elif strength < 5:
            self.strength_var.set("Strong")
            self.strength_label.config(foreground="green")
        else:
            self.strength_var.set("Very Strong")
            self.strength_label.config(foreground="darkgreen")

    def generate_password(self):
        threading.Thread(target=self._generate_with_animation).start()

    def _generate_with_animation(self):
        self.progress_var.set(0)
        self.status_var.set("Generating password...")
        for i in range(101):
            self.progress_var.set(i)
            time.sleep(0.01)  # 1 second total
            self.root.update_idletasks()
        # Play sound
        winsound.Beep(800, 500)  # Hacking sound
        # Now generate
        length = self.length_var.get()
        chars = ""
        if self.upper_var.get():
            chars += string.ascii_uppercase
        if self.lower_var.get():
            chars += string.ascii_lowercase
        if self.digits_var.get():
            chars += string.digits
        if self.symbols_var.get():
            chars += string.punctuation

        if self.exclude_similar_var.get():
            chars = chars.translate(str.maketrans('', '', '0OIl1'))

        if not chars:
            messagebox.showerror("Error", "Select at least one character type")
            return

        password = ''.join(random.choice(chars) for _ in range(length))

        # Shuffle to avoid predictable patterns
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)

        # Incorporate name if selected
        if self.include_name_var.get():
            name = self.name_var.get().strip()
            if name:
                # Insert name at a random position
                insert_pos = random.randint(0, len(password))
                password = password[:insert_pos] + name + password[insert_pos:]
                # Trim to length if exceeds
                if len(password) > length:
                    password = password[:length]

        self.progress_var.set(100)
        self.password_var.set(password)
        self.update_strength()
        self.status_var.set(f"Password generate ho gaya of length {len(password)}")

        # Calculate crack time
        crack_time = self.calculate_crack_time(length, chars)
        self.crack_time_var.set(f"Crack time: {crack_time}")

    def calculate_crack_time(self, length, chars):
        char_count = len(chars)
        combinations = char_count ** length
        attempts_per_second = 1e9  # Assume 1 billion attempts/sec
        seconds = combinations / attempts_per_second
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        else:
            return f"{seconds/31536000:.2f} years"

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.status_var.set("Password copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No password to copy")

    def save_current_password(self):
        password = self.password_var.get()
        if password:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(password + '\n')
                self.status_var.set(f"Password saved to {file_path}")
        else:
            messagebox.showwarning("Warning", "No password to save")

    def clear_password(self):
        self.password_var.set("")
        self.status_var.set("Password cleared")

    def copy_from_history(self, event):
        selection = self.history_listbox.curselection()
        if selection:
            password = self.history_listbox.get(selection[0])
            self.password_var.set(password)
            self.copy_to_clipboard()

    def save_passwords(self):
        if not self.passwords:
            messagebox.showwarning("Warning", "No passwords to save")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.passwords, f)
            self.status_var.set(f"Passwords saved to {file_path}")

    def load_passwords(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'r') as f:
                self.passwords = json.load(f)
            self.history_listbox.delete(0, tk.END)
            for pwd in self.passwords:
                self.history_listbox.insert(tk.END, pwd)
            self.status_var.set(f"Passwords loaded from {file_path}")

    def clear_history(self):
        self.passwords.clear()
        self.history_listbox.delete(0, tk.END)
        self.status_var.set("History cleared")

    def export_as_text(self):
        if not self.passwords:
            messagebox.showwarning("Warning", "No passwords to export")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as f:
                for pwd in self.passwords:
                    f.write(pwd + '\n')
            self.status_var.set(f"Passwords exported to {file_path}")

    def show_about(self):
        messagebox.showinfo("About", "Modern Password Generator\nVersion 2.0\nBuilt with Tkinter\nFeatures: Advanced configurations, strength meter, requirements")

    def show_creator_info(self):
        messagebox.showinfo("Creator", "This application is developed and maintained by UnixDroid, founded and owned by Pushpendra Vishwakarma.")

    def show_terms_and_conditions(self):
        messagebox.showinfo("Terms & Conditions", "Please read our Terms and Conditions carefully.\n\nBy using this Modern Password Generator Tool by UnixDroid, you agree that it is for educational purposes only, no passwords are stored, and UnixDroid is not responsible for misuse or any resulting damages (Last updated: 25 December 2025).")

    def show_privacy_policy(self):
        messagebox.showinfo("Privacy Policy", "Your privacy is important to us.\n\nPrivacy Policy: UnixDroid’s Modern Password Generator Tool does not collect, store, share, or track any personal data or generated passwords; all processing occurs in real time only (Last updated: 25 December 2025). All generated passwords and history are stored locally on your device.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()