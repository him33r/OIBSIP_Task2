import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

#Password Generator
class PasswordGenerator(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Password Generator made by Himanshu")
        self.geometry("450x400")
        self.resizable(False, False)

        #Password complexity options
        self.include_uppercase = tk.BooleanVar()
        self.include_lowercase = tk.BooleanVar()
        self.include_digits = tk.BooleanVar()
        self.include_special = tk.BooleanVar()
        self.password_length = tk.IntVar(value=12)
        self.exclude_chars = tk.StringVar()

        #GUI
        self.create_widgets()

    def create_widgets(self):
        #Password Length
        ttk.Label(self, text="Password Length:").pack(pady=10)
        length_frame = ttk.Frame(self)
        length_frame.pack(pady=5)
        ttk.Entry(length_frame, textvariable=self.password_length, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Label(length_frame, text="characters").pack(side=tk.LEFT)

        #Checkboxes for complexity options
        ttk.Checkbutton(self, text="Include Uppercase Letters", variable=self.include_uppercase).pack(anchor=tk.W)
        ttk.Checkbutton(self, text="Include Lowercase Letters", variable=self.include_lowercase).pack(anchor=tk.W)
        ttk.Checkbutton(self, text="Include Digits", variable=self.include_digits).pack(anchor=tk.W)
        ttk.Checkbutton(self, text="Include Special Characters", variable=self.include_special).pack(anchor=tk.W)

        #Exclude Characters
        ttk.Label(self, text="Exclude Characters:").pack(pady=10)
        ttk.Entry(self, textvariable=self.exclude_chars, width=30).pack(pady=5)

        #Generate button
        ttk.Button(self, text="Generate Password", command=self.generate_password).pack(pady=20)

        #Result Entry
        self.result_entry = ttk.Entry(self, font=("Helvetica", 14), state='readonly', justify='center')
        self.result_entry.pack(pady=10, fill=tk.X, padx=20)

        #Copy to clipboard button
        ttk.Button(self, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=10)

    def generate_password(self):
        length = self.password_length.get()
        include_uppercase = self.include_uppercase.get()
        include_lowercase = self.include_lowercase.get()
        include_digits = self.include_digits.get()
        include_special = self.include_special.get()
        exclude_chars = set(self.exclude_chars.get())

        if length < 6:
            messagebox.showerror("Input Error", "Password length should be at least 6 characters.")
            return

        char_set = ''
        if include_uppercase:
            char_set += string.ascii_uppercase
        if include_lowercase:
            char_set += string.ascii_lowercase
        if include_digits:
            char_set += string.digits
        if include_special:
            char_set += string.punctuation

        if not char_set:
            messagebox.showerror("Input Error", "Select at least one character type.")
            return

        #Filter out excluded characters
        char_set = ''.join(c for c in char_set if c not in exclude_chars)

        if not char_set:
            messagebox.showerror("Input Error", "No characters available for password after exclusions.")
            return

        password = ''.join(random.choice(char_set) for _ in range(length))

        #Ensure the password contains at least one character from each selected category
        def ensure_contains(selected_set, check_set):
            if selected_set and not any(c in check_set for c in password):
                return random.choice(check_set - exclude_chars)
            return ''

        replacements = [
            ensure_contains(include_uppercase, set(string.ascii_uppercase)),
            ensure_contains(include_lowercase, set(string.ascii_lowercase)),
            ensure_contains(include_digits, set(string.digits)),
            ensure_contains(include_special, set(string.punctuation)),
        ]

        #Replace random positions in the password if necessary
        for replacement in replacements:
            if replacement:
                idx = random.randint(0, len(password) - 1)
                password = password[:idx] + replacement + password[idx + 1:]

        #Display password
        self.result_entry.config(state=tk.NORMAL)
        self.result_entry.delete(0, tk.END)
        self.result_entry.insert(0, password)
        self.result_entry.config(state='readonly')

    def copy_to_clipboard(self):
        password = self.result_entry.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard.")

if __name__ == "__main__":
    app = PasswordGenerator()
    app.mainloop()
