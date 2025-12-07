# BioCrypt Authentication System - Dataset Mode

A hybrid authentication system combining facial biometrics, password features, lightweight cryptography (Shift-AES), and blockchain to enhance data integrity, security, and resistance to spoofing in modern digital environments.

## Overview

This system provides a secure multi-factor authentication mechanism that uses:
- **Facial Recognition**: Deep learning-based face verification using VGG-Face and DeepFace
- **Password Authentication**: SHA-256 hashed password storage
- **Blockchain**: Immutable record of authentication patterns
- **AES-256 Encryption**: Secure storage of sensitive biometric data

## Dataset

This project uses the **VGGFace2** dataset for facial recognition.

**Dataset Source**: [VGGFace2 on Kaggle](https://www.kaggle.com/datasets/hearfool/vggface2)

## Setup Instructions

### 1. Install Dependencies

```bash
pip install opencv-python pillow numpy pycryptodome deepface tensorflow
```

### 2. Download Dataset

Download the VGGFace2 dataset from [Kaggle](https://www.kaggle.com/datasets/hearfool/vggface2) and extract it to your project directory.

### 3. Prepare Dataset

Run `dataset.ipynb` to redistribute images from the validation folder to the training folder (60% moved to train, 40% remain in validation).

### 4. Run Application

```bash
python newApp.py
```

## Usage

### Registration
1. Open the **Register** tab
2. Enter User ID and Password
3. Select a person from the dataset
4. Click **Register User**

### Login
1. Open the **Login** tab
2. Enter User ID and Password
3. Click **Verify Login**

The system will automatically select a validation image and verify both password and face.

## How It Works

- **Registration**: Stores password hash and facial biometric from training dataset
- **Login**: Verifies password and compares validation image with registered training image
- Both password and face must match for successful authentication

## Security Features

- **AES-256 Encryption** for biometric data
- **SHA-256 Hashing** for passwords
- **Blockchain** for audit trails
- **Multi-model Face Verification** (VGG-Face, Facenet)

  year   = "2018"
}
```
