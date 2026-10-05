import os
import sys
import io
import json

# Dam bao terminal Windows khong bi loi ma hoa font Unicode/Emoji
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
import xgboost as xgb
import lightgbm as lgb
import joblib

def train_behavior_pipeline():
    print("=" * 60)
    print("🚀 BẮT ĐẦU HUẤN LUYỆN MÔ HÌNH HÀNH VI TIẾN TRÌNH & BỘ NHỚ (100.000 MẪU)")
    print("=" * 60)

    data_path = os.path.join("data", "dataset_behavior_100k.csv")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Không tìm thấy file: {data_path}")

    # 1. Đọc dữ liệu
    print("[*] Đang đọc tập dữ liệu 100.000 mẫu...")
    df = pd.read_csv(data_path)
    print(f"[*] Đã tải thành công. Kích thước: {df.shape[0]} mẫu, {df.shape[1]} cột.")

    # 2. Xử lý nhãn và đặc trưng
    df["label"] = (df["classification"].str.lower() == "malware").astype(int)
    ignore_cols = ["hash", "classification", "label"]
    features = [c for c in df.columns if c not in ignore_cols]

    X = df[features].copy()
    y = df["label"].copy()

    # Xử lý missing values nếu có
    X = X.fillna(0)

    count_mal = (y == 1).sum()
    count_ben = (y == 0).sum()
    print(f"[*] Số lượng đặc trưng: {len(features)}")
    print(f"[*] Phân bố nhãn: Lành tính (0) = {count_ben}, Mã độc (1) = {count_mal} (Cân bằng hoàn hảo 50/50)")

    # 3. Phân chia Train / Test (80% / 20%)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[*] Tập Train: {X_train.shape[0]} mẫu | Tập Test: {X_test.shape[0]} mẫu")

    # 4. Định nghĩa các thuật toán Machine Learning tối ưu tốc độ và độ chính xác
    models = {
        "LightGBM": lgb.LGBMClassifier(n_estimators=150, max_depth=8, learning_rate=0.1, random_state=42, verbose=-1, n_jobs=-1),
        "XGBoost": xgb.XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    }

    results = {}
    best_f1 = 0
    best_model_name = None
    best_model = None

    print("\n" + "-" * 60)
    print(f"{'Mô hình':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'AUC':<10}")
    print("-" * 60)

    for name, clf in models.items():
        print(f"[*] Đang huấn luyện {name}...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_prob)

        results[name] = {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "ROC-AUC": auc
        }

        print(f"{name:<20} | {acc:<10.4f} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f} | {auc:<10.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = clf

    print("-" * 60)
    print(f"🏆 Mô hình xuất sắc nhất: {best_model_name} với F1-Score = {best_f1:.4f}")

    # 5. Lưu mô hình tốt nhất
    os.makedirs("models", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    model_save_path = os.path.join("models", "behavior_detector_model.pkl")
    features_save_path = os.path.join("models", "behavior_features.json")

    joblib.dump(best_model, model_save_path)
    with open(features_save_path, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=4)

    print(f"[✓] Đã lưu mô hình tại: {model_save_path}")
    print(f"[✓] Đã lưu danh sách đặc trưng tại: {features_save_path}")

    # 6. Xuất biểu đồ trực quan hóa cho Báo cáo cuối kỳ
    y_best_pred = best_model.predict(X_test)
    cm = confusion_matrix(y_test, y_best_pred)

    # 6.1 Ma trận nhầm lẫn
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Purples",
                xticklabels=["Lành tính (0)", "Mã độc (1)"],
                yticklabels=["Lành tính (0)", "Mã độc (1)"])
    plt.title(f"Ma trận nhầm lẫn - Hành vi Tiến trình & Bộ nhớ\n({best_model_name})")
    plt.ylabel("Thực tế")
    plt.xlabel("Dự đoán")
    plt.tight_layout()
    cm_path = os.path.join("reports", "behavior_confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[✓] Đã lưu biểu đồ Ma trận nhầm lẫn tại: {cm_path}")

    # 6.2 Top Đặc trưng quan trọng
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        feat_df = pd.DataFrame({"Feature": features, "Importance": importances})
        feat_df = feat_df.sort_values(by="Importance", ascending=False).head(15)

        plt.figure(figsize=(10, 6))
        sns.barplot(data=feat_df, x="Importance", y="Feature", hue="Feature", palette="magma", legend=False)
        plt.title(f"Top 15 Đặc trưng Hành vi / Bộ nhớ quan trọng nhất ({best_model_name})")
        plt.xlabel("Mức độ quan trọng (Feature Importance)")
        plt.ylabel("Đặc trưng Tiến trình")
        plt.tight_layout()
        fi_path = os.path.join("reports", "behavior_feature_importance.png")
        plt.savefig(fi_path, dpi=300)
        plt.close()
        print(f"[✓] Đã lưu biểu đồ Top Đặc trưng tại: {fi_path}")

    # 6.3 So sánh mô hình
    df_results = pd.DataFrame(results).T
    plt.figure(figsize=(9, 5))
    df_results[["Accuracy", "Precision", "Recall", "F1-Score"]].plot(kind="bar", figsize=(10, 5), colormap="plasma")
    plt.title("So sánh Hiệu Năng Các Thuật Toán (Dataset 100.000 Mẫu)")
    plt.ylabel("Điểm số (0 - 1)")
    plt.ylim(0.90, 1.01)
    plt.xticks(rotation=0)
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.legend(loc="lower right")
    plt.tight_layout()
    comp_path = os.path.join("reports", "behavior_model_comparison.png")
    plt.savefig(comp_path, dpi=300)
    plt.close()
    print(f"[✓] Đã lưu biểu đồ So sánh mô hình tại: {comp_path}")

    # 6.4 File tóm tắt số liệu JSON
    summary_path = os.path.join("reports", "behavior_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "best_model": best_model_name,
            "metrics": results[best_model_name],
            "all_results": results,
            "total_samples": len(df),
            "feature_count": len(features)
        }, f, indent=4)

    print(f"[✓] Đã xuất báo cáo tổng kết JSON tại: {summary_path}")
    print("\n🎉 HUẤN LUYỆN 100K BEHAVIOR MODEL HOÀN TẤT!")

if __name__ == "__main__":
    train_behavior_pipeline()
