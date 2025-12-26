# Cybersecurity IDS System

This is a Network Intrusion Detection System (IDS) Dashboard built with Python and Flask. It uses a Random Forest model trained on the KDDCup99 dataset to detect malicious network traffic.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1.  **Install Dependencies**:
    Open a terminal in this directory and run:
    ```bash
    pip install -r requirements.txt
    ```

    *Note: On Windows, `scapy` may require [Npcap](https://npcap.com/) to be installed for packet sniffing features, though this project mainly uses simulated traffic.*

## Usage

### 1. Train the Model (Optional)
The project comes with pre-trained models in the `models/` directory. If you want to retrain them:

```bash
python train_model.py
```
This will download the dataset, train the model, and save `.pkl` files to the `models/` folder.

### 2. Run the Dashboard
Start the Flask application:

```bash
python app.py
```

### 3. Access the Dashboard
Open your web browser and go to:
[http://localhost:5000](http://localhost:5000)

## Project Structure

- `app.py`: Main Flask application and dashboard logic.
- `train_model.py`: Script to train the Machine Learning model.
- `models/`: Stores trained models (`fl_ids_model.pkl`, etc.).
- `templates/` & `static/`: HTML and CSS/JS for the dashboard.
- `logs/` & `reports/`: Generated logs and security reports.
