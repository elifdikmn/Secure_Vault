import tkinter as tk
from tkinter import messagebox, filedialog  
import json
from vault import create_vault, verify_password, lock_vault, derive_encryption_key  
from file_operations import add_file_to_vault, extract_file_from_vault,remove_file_from_vault

class SecureVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Vault")
        
        # Initialize variables
        self.password = None
        self.encryption_key = None
        self.vault_data = None  # Store vault data
        
        # Set up the layout
        self.create_widgets()
        
    def create_widgets(self):
        """Create and place all GUI widgets."""
        
        self.label = tk.Label(self.root, text="Welcome to Secure File Vault", font=("Arial", 14))
        self.label.pack(pady=20)

        self.create_button = tk.Button(self.root, text="Create Vault", command=self.create_vault_ui)
        self.create_button.pack(pady=10)
        
        self.unlock_button = tk.Button(self.root, text="Unlock Vault", command=self.unlock_vault_ui)
        self.unlock_button.pack(pady=10)
        
    def create_vault_ui(self):
        """Create a new vault (create vault screen)."""
        self.clear_widgets()
        
        self.vault_label = tk.Label(self.root, text="Enter a secure password to create the vault:")
        self.vault_label.pack(pady=10)
        
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=10)
        
        self.submit_button = tk.Button(self.root, text="Create Vault", command=self.create_vault)
        self.submit_button.pack(pady=10)
        
        self.back_button = tk.Button(self.root, text="Back", command=self.back_to_main)
        self.back_button.pack(pady=10)
        
    def create_vault(self):
        """Handle vault creation."""
        password = self.password_entry.get()
        if password:
            create_vault(password)
            messagebox.showinfo("Success", "Vault created successfully!")
            self.back_to_main()
        else:
            messagebox.showerror("Error", "Password cannot be empty.")
    
    def unlock_vault_ui(self):
        """Unlock an existing vault (unlock vault screen)."""
        self.clear_widgets()
        
        self.unlock_label = tk.Label(self.root, text="Enter your password to unlock the vault:")
        self.unlock_label.pack(pady=10)
        
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=10)
        
        self.submit_button = tk.Button(self.root, text="Unlock Vault", command=self.unlock_vault)
        self.submit_button.pack(pady=10)
        
        self.back_button = tk.Button(self.root, text="Back", command=self.back_to_main)
        self.back_button.pack(pady=10)
        
    def unlock_vault(self):
        """Verify password and unlock vault."""
        password = self.password_entry.get()
        if password:
            try:
                with open('vaults/vault.json', 'r') as vault_file:
                    self.vault_data = json.load(vault_file)  # Load vault metadata
                
                # Verify password and derive encryption key
                self.encryption_key = derive_encryption_key(password, self.vault_data['salt'])
            
                # Compare derived key with stored hashed key
                if verify_password(password, self.vault_data['salt'], self.vault_data['hashed_key']):
                    messagebox.showinfo("Success", "Vault unlocked successfully!")
                    self.show_vault_actions()  # Show file actions after unlocking the vault
                else:
                    messagebox.showerror("Error", "Incorrect password.")
            except FileNotFoundError:
                messagebox.showerror("Error", "Vault file not found. Please create a vault first.")
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Vault file is corrupted.")
        else:
            messagebox.showerror("Error", "Password cannot be empty.")

    
    def show_vault_actions(self):
        """Show options for adding/extracting files once the vault is unlocked."""
        self.clear_widgets()

        self.add_file_button = tk.Button(self.root, text="Add File", command=self.add_file_ui)
        self.add_file_button.pack(pady=10)

        self.extract_file_button = tk.Button(self.root, text="Extract File", command=self.extract_file_ui)
        self.extract_file_button.pack(pady=10)

        self.remove_file_button = tk.Button(self.root, text="Remove File", command=self.remove_file_ui)
        self.remove_file_button.pack(pady=10)

        # Button to view the list of files
        self.view_files_button = tk.Button(self.root, text="View Files", command=lambda: self.view_files(self.vault_data))
        self.view_files_button.pack(pady=10)

        # Button to lock the vault again
        self.lock_vault_button = tk.Button(self.root, text="Lock Vault", command=self.lock_vault)
        self.lock_vault_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back", command=self.back_to_main)
        self.back_button.pack(pady=10)
    
    def view_files(self, vault_data):
        """Display a list of files stored in the vault."""
        self.clear_widgets()
        
        # Display a list of filenames (metadata only)
        file_list_label = tk.Label(self.root, text="Files in Vault:")
        file_list_label.pack(pady=10)
        
        if 'files' in vault_data and vault_data['files']:
            for file in vault_data['files']:
                file_name_label = tk.Label(self.root, text=file['name'])
                file_name_label.pack(pady=2)
        else:
            messagebox.showinfo("No files", "No files found in the vault.")
        
        # Back button to return to vault actions
        self.back_button = tk.Button(self.root, text="Back", command=self.show_vault_actions)
        self.back_button.pack(pady=10)

    def add_file_ui(self):
        """UI for adding a file to the vault."""
        self.clear_widgets()

        self.add_file_label = tk.Label(self.root, text="Select the file to add:")
        self.add_file_label.pack(pady=10)

        # Add a button to open file dialog to select a file
        self.select_file_button = tk.Button(self.root, text="Select File", command=self.select_file)
        self.select_file_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back", command=self.show_vault_actions)
        self.back_button.pack(pady=10)
    
    def select_file(self):
        """Open a file dialog to select a file."""
        file_path = filedialog.askopenfilename(title="Select a File")  # Open file dialog to select a file
        if file_path:
            self.add_file(file_path)  # If file is selected, call the add_file method
    
    def add_file(self, file_path):
        """Handle adding a file to the vault."""
        if file_path:
            add_file_to_vault(file_path, self.encryption_key)
            messagebox.showinfo("Success", "File added to vault.")
            self.show_vault_actions()  # Show file actions after adding the file
        else:
            messagebox.showerror("Error", "File path cannot be empty.")
        self.update_file_list()
        
    def extract_file_ui(self):
        """UI for extracting a file from the vault."""
        self.clear_widgets()

        self.extract_file_label = tk.Label(self.root, text="Enter the file name to extract:")
        self.extract_file_label.pack(pady=10)

        self.file_name_entry = tk.Entry(self.root)
        self.file_name_entry.pack(pady=10)

        self.submit_button = tk.Button(self.root, text="Extract File", command=self.extract_file)
        self.submit_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back", command=self.show_vault_actions)
        self.back_button.pack(pady=10)
    
    def extract_file(self):
        """Handle extracting a file from the vault."""
        file_name = self.file_name_entry.get()
        if file_name:
            extract_file_from_vault(file_name, self.encryption_key)
            messagebox.showinfo("Success", f"File {file_name} extracted successfully.")
            self.show_vault_actions()  # Show file actions after extracting the file
        else:
            messagebox.showerror("Error", "File name cannot be empty.")


    def remove_file_ui(self):
       """UI for removing a file from the vault."""
       self.clear_widgets()

       self.remove_file_label = tk.Label(self.root, text="Enter the file name to remove:")
       self.remove_file_label.pack(pady=10)

       self.file_name_entry = tk.Entry(self.root)
       self.file_name_entry.pack(pady=10)

       self.submit_button = tk.Button(self.root, text="Remove File", command=self.remove_file)
       self.submit_button.pack(pady=10)

       self.back_button = tk.Button(self.root, text="Back", command=self.show_vault_actions)
       self.back_button.pack(pady=10)

    def remove_file(self):
       """Handle removing a file from the vault."""
       file_name = self.file_name_entry.get()
       if file_name:
           # Call the function to remove the file from the vault
            if remove_file_from_vault(file_name, self.encryption_key):
                messagebox.showinfo("Success", f"File {file_name} removed successfully.")
                self.update_file_list()
            else:
                messagebox.showerror("Error", f"File {file_name} not found in the vault.")
       else:
            messagebox.showerror("Error", "File name cannot be empty.")

    def update_file_list(self):
        """Update the file list after an operation (e.g., removing a file)."""
        self.view_files(self.vault_data)
    
    def lock_vault(self):
        """Lock the vault (re-encrypt it)."""
        if self.vault_data and self.encryption_key:
            print("Vault Data Before Lock:", self.vault_data)
            
            try:
                # Call the lock_vault function with the entire vault data
                lock_vault(self.vault_data)  # Ensure lock_vault handles encryption properly
                messagebox.showinfo("Success", "Vault locked successfully.")
                self.back_to_main()  # Go back to the main screen
            except Exception as e:
                messagebox.showerror("Error", f"Failed to lock vault: {e}")
        else:
            messagebox.showerror("Error", "Vault data or encryption key missing.")
    
    def clear_widgets(self):
        """Clear all widgets from the window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def back_to_main(self):
        """Back to the main screen."""
        self.clear_widgets()
        self.create_widgets()

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVaultApp(root)
    root.mainloop()
