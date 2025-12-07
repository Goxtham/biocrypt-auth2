import hashlib
import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import cv2
import json
from datetime import datetime
import sqlite3
import time
import tkinter as tk
from tkinter import ttk, messagebox, Listbox, Scrollbar
import threading
from PIL import Image, ImageTk
from deepface import DeepFace
from tensorflow.keras.applications import VGG16
from tensorflow.keras.applications.vgg16 import preprocess_input
from tensorflow.keras.models import Model
import random


class HybridCryptoAuth:
    def __init__(self, db_path='auth_system.db', dataset_path=r'C:\Users\goxth\Documents\COLLEGE WORKS\FINAL YEAR PROJECT\BioCrypt-Auth\Dataset'):
        self.db_path = db_path
        self.dataset_path = dataset_path
        self.train_path = os.path.join(dataset_path, 'train')
        
        # Check for validation folder - try both 'val' and 'test'
        val_folder = os.path.join(dataset_path, 'val')
        test_folder = os.path.join(dataset_path, 'test')
        
        if os.path.exists(val_folder):
            self.val_path = val_folder
            print(f"Using validation folder: {val_folder}")
        elif os.path.exists(test_folder):
            self.val_path = test_folder
            print(f"Using test folder: {test_folder}")
        else:
            raise Exception(f"Neither 'val' nor 'test' folder found in {dataset_path}")
        
        # Initialize database FIRST
        self.init_db()
        
        self.key_file = 'encryption_key.bin'
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()[:32]
        else:
            self.key = get_random_bytes(32)[:32]  # AES-256 key
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        
        self.blockchain = []
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Initialize CNN model for face embeddings
        base_model = VGG16(weights='imagenet', include_top=False)
        self.face_model = Model(inputs=base_model.input, 
                              outputs=base_model.get_layer('block5_pool').output)

    def init_db(self):
        """Initialize the SQLite database with migration support"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            table_exists = cursor.fetchone() is not None
            
            if table_exists:
                # Check if new columns exist
                cursor.execute("PRAGMA table_info(users)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'person_id' not in columns:
                    cursor.execute('ALTER TABLE users ADD COLUMN person_id TEXT')
                    print("Added person_id column")
                
                if 'train_image_path' not in columns:
                    cursor.execute('ALTER TABLE users ADD COLUMN train_image_path TEXT')
                    print("Added train_image_path column")
                
                if 'password_hash' not in columns:
                    cursor.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')
                    print("Added password_hash column")
            else:
                # Create new table with all columns
                cursor.execute('''
                    CREATE TABLE users (
                        user_id TEXT PRIMARY KEY,
                        person_id TEXT,
                        train_image_path TEXT,
                        password_hash TEXT,
                        encrypted_pattern BLOB,
                        block_hash TEXT
                    )
                ''')
                print("Created new users table")
            
            conn.commit()
            conn.close()
            print("Database initialized successfully")
        except Exception as e:
            print(f"Database initialization error: {str(e)}")
            raise

    def get_available_persons(self):
        """Get list of available person IDs from train folder"""
        if not os.path.exists(self.train_path):
            return []
        persons = [d for d in os.listdir(self.train_path) 
                  if os.path.isdir(os.path.join(self.train_path, d))]
        return sorted(persons)

    def get_person_images(self, person_id, from_train=True):
        """Get all image paths for a specific person"""
        folder_path = self.train_path if from_train else self.val_path
        person_folder = os.path.join(folder_path, person_id)
        
        if not os.path.exists(person_folder):
            return []
        
        images = []
        for file in os.listdir(person_folder):
            if file.lower().endswith(('.jpg', '.jpeg', '.png')):
                images.append(os.path.join(person_folder, file))
        return images

    def load_image(self, image_path):
        """Load and preprocess image"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError(f"Could not load image: {image_path}")
            return img
        except Exception as e:
            raise Exception(f"Error loading image: {str(e)}")

    def password_to_binary(self, password):
        """Convert password to binary string"""
        password_bytes = password.encode('utf-8')
        binary = bin(int.from_bytes(password_bytes, byteorder='big'))[2:]
        return binary.zfill(len(password_bytes) * 8)

    def merge_features(self, eye_binary, face_binary, password_binary):
        """Merge binary features using a simple interleaving pattern"""
        max_length = max(len(eye_binary), len(face_binary), len(password_binary))
        eye_binary = eye_binary.ljust(max_length, '0')
        face_binary = face_binary.ljust(max_length, '0')
        password_binary = password_binary.ljust(max_length, '0')

        merged = ''
        for i in range(max_length):
            merged += eye_binary[i] + face_binary[i] + password_binary[i]
        
        return merged

    def apply_sha256(self, data):
        """Apply SHA-256 hashing"""
        return hashlib.sha256(data.encode()).hexdigest()

    def shift_aes_encrypt(self, data):
        """Encrypt data using AES"""
        cipher = AES.new(self.key, AES.MODE_CBC)
        padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
        encrypted_data = cipher.encrypt(padded_data.encode())
        return cipher.iv + encrypted_data

    def shift_aes_decrypt(self, encrypted_data):
        """Decrypt data using AES"""
        try:
            iv = encrypted_data[:16]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(encrypted_data[16:])
            padding_length = decrypted_data[-1]
            if isinstance(padding_length, str):
                padding_length = ord(padding_length)
            return decrypted_data[:-padding_length].decode()
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise

    def add_to_blockchain(self, user_id, encrypted_pattern):
        """Add encrypted pattern to blockchain"""
        block = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'encrypted_pattern': encrypted_pattern.hex(),
            'previous_hash': self.blockchain[-1]['hash'] if self.blockchain else '0' * 64
        }
        
        block_string = json.dumps(block, sort_keys=True)
        block['hash'] = hashlib.sha256(block_string.encode()).hexdigest()
        
        self.blockchain.append(block)
        return block

    def save_user_to_db(self, user_id, person_id, train_image_path, password_hash, encrypted_pattern, block_hash):
        """Save user data to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (user_id, person_id, train_image_path, password_hash, encrypted_pattern, block_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, person_id, train_image_path, password_hash, encrypted_pattern, block_hash))
        conn.commit()
        conn.close()

    def get_user_from_db(self, user_id):
        """Retrieve user data from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT person_id, train_image_path, password_hash, encrypted_pattern, block_hash FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result

    def user_exists(self, user_id):
        """Check if a user already exists in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users WHERE user_id = ?', (user_id,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def process_face_to_binary(self, face_image):
        """Process face image to binary string consistently"""
        try:
            face_image = cv2.resize(face_image, (256, 256))
            gray = cv2.cvtColor(face_image, cv2.COLOR_BGR2GRAY)
            _, binary = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
            binary_string = ''.join(['1' if pixel == 255 else '0' for pixel in binary.flatten()])
            return binary_string
        except Exception as e:
            raise Exception(f"Error processing face: {str(e)}")

    def register_user(self, user_id, password, person_id, train_image_path):
        """Register a new user with dataset image"""
        try:
            if self.user_exists(user_id):
                raise Exception(f"User ID '{user_id}' already exists. Please choose a different ID.")

            # Load the training image
            face_image = self.load_image(train_image_path)

            # Process face image for blockchain
            face_binary = self.process_face_to_binary(face_image)
            password_binary = self.password_to_binary(password)

            # Create merged pattern for blockchain
            merged_pattern = self.merge_features(face_binary, face_binary, password_binary)
            hashed_pattern = self.apply_sha256(merged_pattern)
            encrypted_pattern = self.shift_aes_encrypt(hashed_pattern)

            # Store separate password hash for verification
            password_hash = self.apply_sha256(password)

            block = self.add_to_blockchain(user_id, encrypted_pattern)
            self.save_user_to_db(user_id, person_id, train_image_path, password_hash, encrypted_pattern, block['hash'])

            print(f"User {user_id} registered successfully with person_id: {person_id}")
            return True

        except Exception as e:
            raise Exception(f"Registration failed: {str(e)}")

    def verify_user(self, user_id, password):
        """Verify user using validation dataset images"""
        try:
            user_data = self.get_user_from_db(user_id)
            if not user_data:
                return False, "User not found in the database."

            person_id, train_image_path, stored_password_hash, stored_encrypted_pattern, stored_block_hash = user_data

            # First verify password independently
            current_password_hash = self.apply_sha256(password)
            
            if current_password_hash != stored_password_hash:
                print("Password verification failed")
                return False, "Invalid password. Please try again."
            
            print("Password verified successfully")

            # Get validation images for this person
            val_images = self.get_person_images(person_id, from_train=False)
            if not val_images:
                return False, f"No validation images found for person {person_id}"

            # Try multiple validation images for face verification
            max_attempts = min(3, len(val_images))
            best_match_score = 0
            best_val_image = None
            
            for i in range(max_attempts):
                val_image_path = random.choice(val_images)
                print(f"\nAttempt {i+1}: Using validation image: {os.path.basename(val_image_path)}")

                # Load both training and validation images
                train_face = self.load_image(train_image_path)
                val_face = self.load_image(val_image_path)

                # Compare faces using DeepFace
                face_match_score = self.compare_faces(train_face, val_face)
                
                if face_match_score > best_match_score:
                    best_match_score = face_match_score
                    best_val_image = val_image_path
                
                # If we get a good match, break early
                if face_match_score > 0:
                    print(f"Face match found on attempt {i+1}")
                    break

            print(f"\nBest face match score: {best_match_score}")

            # Clean up temporary files
            try:
                if os.path.exists("stored_temp.jpg"):
                    os.remove("stored_temp.jpg")
                if os.path.exists("current_temp.jpg"):
                    os.remove("current_temp.jpg")
            except Exception as e:
                print(f"Error deleting temporary images: {e}")

            if best_match_score == 0:
                return False, "Face verification failed. Images don't match sufficiently."

            # Both password and face verified
            return True, f"Login successful! Verified with image: {os.path.basename(best_val_image)}"

        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False, f"Verification failed: {str(e)}"

    def compare_faces(self, stored_face, current_face):
        """Compare faces using DeepFace similarity"""
        try:
            stored_temp_path = "stored_temp.jpg"
            current_temp_path = "current_temp.jpg"
            
            cv2.imwrite(stored_temp_path, stored_face)
            cv2.imwrite(current_temp_path, current_face)
            
            result = DeepFace.verify(stored_temp_path, current_temp_path, 
                                    model_name="VGG-Face",
                                    enforce_detection=False)
            
            distance = result["distance"]
            verified = result["verified"]
            
            print(f"Face comparison - Distance: {distance}, Verified: {verified}")
            
            # Use DeepFace's own verification result
            # VGG-Face typical threshold is around 0.4-0.68
            threshold = 0.68  # More lenient threshold for dataset images
            
            if verified or distance < threshold:
                return 1.0  # Match
            else:
                return 0.0  # No match

        except Exception as e:
            print(f"DeepFace comparison error: {str(e)}")
            # Try with a more lenient approach
            try:
                result = DeepFace.verify(stored_temp_path, current_temp_path, 
                                        model_name="Facenet",
                                        enforce_detection=False)
                distance = result["distance"]
                verified = result["verified"]
                print(f"Facenet comparison - Distance: {distance}, Verified: {verified}")
                
                if verified or distance < 0.6:
                    return 1.0
                else:
                    return 0.0
            except:
                print("Both face comparison methods failed")
                return 0.0


class AuthUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BioCrypt Authentication System - Dataset Mode")
        self.root.geometry("800x600")
        self.auth_system = HybridCryptoAuth()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, expand=True, fill='both')
        
        # Create registration and login tabs
        self.register_frame = ttk.Frame(self.notebook)
        self.login_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.register_frame, text="Register")
        self.notebook.add(self.login_frame, text="Login")
        
        self.setup_register_frame()
        self.setup_login_frame()
        
        self.selected_person_id = None
        self.selected_image_path = None

    def setup_register_frame(self):
        ttk.Label(self.register_frame, text="Registration", font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        # User ID
        ttk.Label(self.register_frame, text="User ID:").pack(pady=5)
        self.register_userid = ttk.Entry(self.register_frame, width=40)
        self.register_userid.pack(pady=5)
        
        # Password
        ttk.Label(self.register_frame, text="Password:").pack(pady=5)
        self.register_password = ttk.Entry(self.register_frame, show="*", width=40)
        self.register_password.pack(pady=5)
        
        # Confirm Password
        ttk.Label(self.register_frame, text="Confirm Password:").pack(pady=5)
        self.register_confirm_password = ttk.Entry(self.register_frame, show="*", width=40)
        self.register_confirm_password.pack(pady=5)
        
        # Person selection
        ttk.Label(self.register_frame, text="Select Person from Dataset:").pack(pady=5)
        
        person_frame = ttk.Frame(self.register_frame)
        person_frame.pack(pady=5, fill='both', expand=True, padx=20)
        
        scrollbar = Scrollbar(person_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.person_listbox = Listbox(person_frame, yscrollcommand=scrollbar.set, height=8)
        self.person_listbox.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.config(command=self.person_listbox.yview)
        
        # Load available persons
        self.load_persons()
        
        self.person_listbox.bind('<<ListboxSelect>>', self.on_person_select)
        
        # Image preview
        self.register_image_label = ttk.Label(self.register_frame, text="No image selected")
        self.register_image_label.pack(pady=10)
        
        # Selected info
        self.register_info_label = ttk.Label(self.register_frame, text="")
        self.register_info_label.pack(pady=5)
        
        # Register button
        ttk.Button(self.register_frame, text="Register User", command=self.register_user).pack(pady=10)

    def setup_login_frame(self):
        ttk.Label(self.login_frame, text="Login", font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        # User ID
        ttk.Label(self.login_frame, text="User ID:").pack(pady=5)
        self.login_userid = ttk.Entry(self.login_frame, width=40)
        self.login_userid.pack(pady=5)
        
        # Password
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.login_password = ttk.Entry(self.login_frame, show="*", width=40)
        self.login_password.pack(pady=5)
        
        # Info label
        self.login_info_label = ttk.Label(self.login_frame, text="System will automatically select a validation image", 
                                         font=('Helvetica', 10, 'italic'))
        self.login_info_label.pack(pady=10)
        
        # Verify button
        ttk.Button(self.login_frame, text="Verify Login", command=self.verify_user).pack(pady=20)

    def load_persons(self):
        """Load available persons from dataset"""
        persons = self.auth_system.get_available_persons()
        self.person_listbox.delete(0, tk.END)
        for person in persons:
            self.person_listbox.insert(tk.END, person)

    def on_person_select(self, event):
        """Handle person selection"""
        selection = self.person_listbox.curselection()
        if selection:
            self.selected_person_id = self.person_listbox.get(selection[0])
            
            # Get images for this person
            images = self.auth_system.get_person_images(self.selected_person_id, from_train=True)
            if images:
                # Select first image by default
                self.selected_image_path = images[0]
                
                # Display image
                try:
                    img = Image.open(self.selected_image_path)
                    img.thumbnail((200, 200))
                    photo = ImageTk.PhotoImage(img)
                    self.register_image_label.configure(image=photo, text="")
                    self.register_image_label.image = photo
                    
                    self.register_info_label.config(
                        text=f"Selected: {self.selected_person_id}\nImages available: {len(images)}"
                    )
                except Exception as e:
                    self.register_info_label.config(text=f"Error loading image: {str(e)}")

    def register_user(self):
        user_id = self.register_userid.get()
        password = self.register_password.get()
        confirm_password = self.register_confirm_password.get()
        
        if not user_id or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return

        if not self.selected_person_id or not self.selected_image_path:
            messagebox.showerror("Error", "Please select a person from the dataset")
            return
        
        try:
            success = self.auth_system.register_user(
                user_id, password, self.selected_person_id, self.selected_image_path
            )
            if success:
                messagebox.showinfo("Success", f"Registration successful!\nUser: {user_id}\nPerson: {self.selected_person_id}")
                # Clear fields
                self.register_userid.delete(0, tk.END)
                self.register_password.delete(0, tk.END)
                self.register_confirm_password.delete(0, tk.END)
                self.register_image_label.configure(image='', text="No image selected")
                self.register_info_label.config(text="")
                self.selected_person_id = None
                self.selected_image_path = None
                # Switch to login tab
                self.notebook.select(self.login_frame)
            else:
                messagebox.showerror("Error", "Registration failed")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_user(self):
        user_id = self.login_userid.get()
        password = self.login_password.get()
        
        if not user_id or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        try:
            success, message = self.auth_system.verify_user(user_id, password)
            if success:
                messagebox.showinfo("Success", message)
                # Clear fields
                self.login_userid.delete(0, tk.END)
                self.login_password.delete(0, tk.END)
            else:
                messagebox.showerror("Error", message)
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = AuthUI(root)
    root.mainloop()