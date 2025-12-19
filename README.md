# SmartDefender

# About

SmartDefender is a machine-learning–based Intrusion Detection System (IDS) designed to detect malicious network traffic with high accuracy using an advanced stacked ensemble model. 
This project applies feature engineering, class imbalance handling, and ensemble learning on the UNSW-NB15 dataset to achieve robust intrusion detection performance.

# Key Features
Advanced feature engineering for network traffic

Handles class imbalance using SMOTE

Stacked Ensemble Model:

1. XGBoost
2. LightGBM
3. Random Forest
4. Logistic Regression (Meta-Learner)
Threshold optimization for improved detection

Robust preprocessing and feature selection

Research-oriented, modular codebase

High accuracy suitable for academic evaluation

# Model Architecture
```
Input Network Traffic
        ↓
Feature Engineering
        ↓
Scaling (RobustScaler)
        ↓
Feature Selection (Top-K ANOVA)
        ↓
SMOTE (Train Data Only)
        ↓
Base Models
  ├── XGBoost
  ├── LightGBM
  └── Random Forest
        ↓
Meta-Learner (Logistic Regression)
        ↓
Final Intrusion Prediction
```
# Project Structure
```
Smartdefender-IDS/
│
├── ai_model/
│   ├── train_model.py        # Main training script
│
├── dataset/
│   ├── UNSW_NB15_training-set.csv
│   ├── UNSW_NB15_testing-set.csv
│
├── models/                   # Saved models (ignored in Git)
│
├── logs/
│   └── training_log.txt
│
├── requirements.txt
├── README.md
├── .gitignore
```
# Datasets
UNSW-NB15 Dataset

Realistic modern network traffic

Normal and attack categories

Features include:

Protocol, service, state
Packet statistics
Byte flow metrics
Timing and jitter attributes

 Target Variable:

1. 0 → Normal Traffic
2. 1 → Attack Traffic
#  Installation
1. Clone the Repository
```
git clone https://github.com/ThakshaRishi/SmartDefender
cd SmartDefender
```
2. Create Virtual Environment
```
python -m venv venv
```
Activate:
```
# Windows

venv\Scripts\activate

# Linux / Mac

source venv/bin/activate
```
3. Install Dependencies
```
pip install -r requirements.txt
```
# Training the Model
Run the training pipeline:
```
cd ai_model
python train_model.py
```
The pipeline performs:

1. Data loading
2. Feature engineering
3. Scaling and feature selection
4. SMOTE balancing
5. Ensemble training
6. Threshold optimization
7. Evaluation
8. Model & metric saving
# Evaluation Metrics
The system evaluates the following metrics:

1. Accuracy
2. Precision
3. Recall
4. F1-Score
5. AUC-ROC

Threshold optimization improves classification reliability.

# Sample Output
```
Accuracy   : 94.99%
Precision  : 96.15%
Recall     : 96.00%
F1 Score   : 96.08%
AUC-ROC    : 99.21%
```
Results may vary slightly depending on system and dataset splits.

# Model Storage Policy
To comply with GitHub size limits:

Trained models (.pkl) are not committed
Models are saved locally under:
```
models/
```
Ignored via .gitignore.

# Applications
1. Network Intrusion Detection
2. Cybersecurity monitoring
3. Research on ensemble learning
4. Academic ML projects
5. Benchmarking IDS models
# Technologies Used
1. Python
2. Scikit-learn
3. XGBoost
4. LightGBM
5. Imbalanced-Learn
6. Pandas, NumPy
7. Joblib
# Future Enhancements
1. Real-time packet capture integration
2. Deep learning models (LSTM / Autoencoders)
3. Live dashboard for traffic monitoring
4. Deployment using Flask / FastAPI
5. Explainable AI (SHAP)

