"""
SmartDefender - AI Research Ensemble Trainer
============================================
This module implements a stacked ensemble learning architecture for 
Intrusion Detection Systems (IDS) using the UNSW-NB15 dataset.

Architecture:
    - Base Learners: XGBoost, LightGBM, Random Forest
    - Meta Learner: Logistic Regression
    - Feature Engineering: Ratio-based interaction features, log-transforms
    - Imbalance Handling: SMOTE
    - Optimization: Threshold moving based on Validation Set

Author: [Dharsan R,Thaksha Rishi,Mandhakini]
Date: 2025
License: MIT
"""

import pandas as pd
import numpy as np
import logging
import sys
import os
import json
from datetime import datetime
import warnings
import joblib

# Sklearn & Models
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, 
    recall_score, roc_auc_score
)
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import SelectKBest, f_classif

# Gradient Boosting
import xgboost as xgb
import lightgbm as lgb

# Imbalanced learning
from imblearn.over_sampling import SMOTE

# Configuration
warnings.filterwarnings("ignore")
LOG_DIR = "../logs"
MODEL_DIR = "models"
DATASET_DIR = "../dataset"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# Logger Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/training_log.txt"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ResearchEnsembleTrainer:
    """
    Handles the end-to-end training pipeline:
    Loading -> Feature Engineering -> Preprocessing -> Stacking -> Evaluation.
    """
    
    def __init__(self):
        self.model = None
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.best_threshold = 0.5
        # Select top 80 features to reduce noise and dimensionality
        self.selector = SelectKBest(score_func=f_classif, k=80) 

    def load_data(self):
        """Loads and combines training and testing datasets."""
        logger.info("Loading UNSW-NB15 dataset...")
        try:
            train_path = os.path.join(DATASET_DIR, "UNSW_NB15_training-set.csv")
            test_path = os.path.join(DATASET_DIR, "UNSW_NB15_testing-set.csv")
            
            train = pd.read_csv(train_path)
            test = pd.read_csv(test_path)
            
            df = pd.concat([train, test], ignore_index=True)
            logger.info(f"Dataset Loaded Successfully: {df.shape}")
            return df
        except FileNotFoundError:
            logger.error(f"Dataset not found in {DATASET_DIR}. Please check the path.")
            sys.exit(1)

    def feature_engineering(self, df):
        """Applies domain-specific transformations for network traffic analysis."""
        logger.info("Applying Advanced Feature Engineering...")
        
        epsilon = 1e-6 # Prevent division by zero

        # --- Interaction Features ---
        df["bytes_ratio"] = df["sbytes"] / (df["dbytes"] + epsilon)
        df["packet_ratio"] = df["spkts"] / (df["dpkts"] + epsilon)
        df["load_ratio"] = df["sload"] / (df["dload"] + epsilon)
        df["tcp_window_ratio"] = df["swin"] / (df["dwin"] + epsilon)
        
        # --- Velocity Features ---
        df["sbytes_per_sec"] = df["sbytes"] / (df["dur"] + epsilon)
        df["dbytes_per_sec"] = df["dbytes"] / (df["dur"] + epsilon)
        df["pkts_per_sec"] = (df["spkts"] + df["dpkts"]) / (df["dur"] + epsilon)
        
        # --- Statistical Aggregations ---
        df["total_bytes"] = df["sbytes"] + df["dbytes"]
        df["total_pkts"] = df["spkts"] + df["dpkts"]
        df["bytes_per_pkt"] = df["total_bytes"] / (df["total_pkts"] + epsilon)
        
        # --- Log-Transformations (Handling Skewness) ---
        skewed_cols = ['sbytes', 'dbytes', 'sload', 'dload', 'spkts', 'dpkts', 
                       'dur', 'sjit', 'djit', 'total_bytes', 'total_pkts']
        for col in skewed_cols:
            if col in df.columns:
                df[f"log_{col}"] = np.log1p(df[col])
        
        # Clean infinite values resulting from calculations
        df = df.replace([np.inf, -np.inf], 0).fillna(0)
        
        return df

    def preprocess(self, df):
        """Encodes targets and categorical features."""
        drop_cols = ["id", "attack_cat", "label"]
        y = self.label_encoder.fit_transform(df["label"])
        
        X = df.drop(columns=drop_cols, errors="ignore")
        X = pd.get_dummies(X, columns=["proto", "service", "state"], drop_first=True)
        
        return X, y

    def build_ensemble(self, X_train, y_train):
        """Defines the Stacking Classifier architecture."""
        logger.info("Constructing Stacked Ensemble (XGB + LGB + RF -> LogReg)...")
        
        # Base Learners
        clf_xgb = xgb.XGBClassifier(
            n_estimators=500, max_depth=10, learning_rate=0.03,
            subsample=0.8, colsample_bytree=0.8, eval_metric="logloss",
            tree_method="hist", random_state=42, n_jobs=-1
        )
        
        clf_lgb = lgb.LGBMClassifier(
            n_estimators=500, max_depth=12, learning_rate=0.03,
            subsample=0.8, class_weight='balanced', random_state=42, n_jobs=-1,
            verbose=-1
        )
        
        clf_rf = RandomForestClassifier(
            n_estimators=200, max_depth=25, class_weight='balanced',
            random_state=42, n_jobs=-1
        )

        # Stacking Ensemble
        stacking_clf = StackingClassifier(
            estimators=[
                ('xgb', clf_xgb),
                ('lgb', clf_lgb),
                ('rf', clf_rf)
            ],
            final_estimator=LogisticRegression(random_state=42, max_iter=1000),
            cv=3,
            n_jobs=-1,
            passthrough=False
        )
        
        return stacking_clf

    def optimize_threshold(self, model, X_val, y_val):
        """Finds the optimal probability threshold to maximize Accuracy."""
        logger.info("Optimizing Decision Threshold on Validation Set...")
        y_probs = model.predict_proba(X_val)[:, 1]
        
        thresholds = np.arange(0.3, 0.7, 0.005)
        best_acc = 0
        best_thresh = 0.5
        
        for thresh in thresholds:
            y_pred_temp = (y_probs >= thresh).astype(int)
            acc = accuracy_score(y_val, y_pred_temp)
            if acc > best_acc:
                best_acc = acc
                best_thresh = thresh
                
        logger.info(f"Optimization Complete. Best Threshold: {best_thresh:.4f} (Val Acc: {best_acc:.4f})")
        return best_thresh

    def train(self):
        """Executes the full training workflow."""
        # 1. Load
        df = self.load_data()
        
        # 2. Feature Engineering
        df = self.feature_engineering(df)
        
        # 3. Preprocess
        X, y = self.preprocess(df)
        
        # 4. Split (Train: 70%, Val: 15%, Test: 15%)
        logger.info("Splitting Data into Train/Val/Test...")
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=0.15, stratify=y, random_state=42
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=0.176, stratify=y_temp, random_state=42
        )
        
        # 5. Scaling
        logger.info("Scaling Features (RobustScaler)...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)
        
        # 6. Feature Selection
        logger.info("Selecting Top 80 Features...")
        X_train_sel = self.selector.fit_transform(X_train_scaled, y_train)
        X_val_sel = self.selector.transform(X_val_scaled)
        X_test_sel = self.selector.transform(X_test_scaled)
        
        # 7. SMOTE (Balancing)
        logger.info("Applying SMOTE balancing to Training Data...")
        smote = SMOTE(random_state=42)
        X_train_sm, y_train_sm = smote.fit_resample(X_train_sel, y_train)
        
        # 8. Train
        logger.info("Training Stacked Ensemble (This may take time)...")
        self.model = self.build_ensemble(X_train_sm, y_train_sm)
        self.model.fit(X_train_sm, y_train_sm)
        
        # 9. Threshold Optimization
        self.best_threshold = self.optimize_threshold(self.model, X_val_sel, y_val)
        
        # 10. Final Evaluation
        logger.info("Evaluating on Test Set...")
        y_probs = self.model.predict_proba(X_test_sel)[:, 1]
        y_pred = (y_probs >= self.best_threshold).astype(int)
        
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "f1": f1_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "auc": roc_auc_score(y_test, y_probs)
        }
        
        self.save_artifacts(metrics)
        return metrics

    def save_artifacts(self, metrics):
        """Saves model, scaler, selector, and metrics to disk."""
        version = datetime.now().strftime("v8_%Y%m%d")
        
        joblib.dump(self.model, f"{MODEL_DIR}/ensemble_{version}.pkl")
        joblib.dump(self.scaler, f"{MODEL_DIR}/scaler_{version}.pkl")
        joblib.dump(self.selector, f"{MODEL_DIR}/selector_{version}.pkl")
        
        metrics["version"] = f"v8 (Stacked) - {version}"
        metrics["best_threshold"] = self.best_threshold
        
        with open(f"{MODEL_DIR}/metrics_{version}.json", "w") as f:
            json.dump(metrics, f, indent=4)
        logger.info(f"Model artifacts saved to {MODEL_DIR}/")


def main():
    """Main execution entry point."""
    print("="*60)
    print("  SmartDefender Research Training Pipeline (v8.1)  ")
    print("="*60)
    
    try:
        trainer = ResearchEnsembleTrainer()
        metrics = trainer.train()
        
        print("\n" + "="*60)
        print("  FINAL EVALUATION RESULTS  ")
        print("="*60)
        print(f"Accuracy   : {metrics['accuracy']*100:.2f}%")
        print(f"F1 Score   : {metrics['f1']*100:.2f}%")
        print(f"Precision  : {metrics['precision']*100:.2f}%")
        print(f"Recall     : {metrics['recall']*100:.2f}%")
        print(f"AUC-ROC    : {metrics['auc']:.4f}")
        print("="*60 + "\n")
        
    except KeyboardInterrupt:
        logger.warning("Training interrupted by user.")
    except Exception as e:
        logger.critical(f"Fatal Error: {e}", exc_info=True)

if __name__ == "__main__":
    main()