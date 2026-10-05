import os
import sys
import io
import json

# Dam bao terminal Windows hien thi dung font tieng Viet khong bi loi cp1252
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import xgboost as xgb
import lightgbm as lgb
import joblib

def train_pdf_pipeline():
    print("=" * 60)
    print("🚀 BẮT ĐẦU HUẤN LUYỆN MÔ HÌNH NHẬN DIỆN MÃ ĐỘC TÀI LIỆU PDF")
    print("=" * 60)

    clean_path = os.path.join("data", "dataset_pdf_clean.csv")
    if not os.path.exists(clean_path):
        raise FileNotFoundError(f"Không tìm thấy file: {clean_path}")

    # 1. Đọc dữ liệu
    df = pd.read_csv(clean_path)
    print(f"[*] Đã tải dữ liệu PDF thành công. Tổng số mẫu: {df.shape[0]} mẫu, {df.shape[1]} cột.")

    # 2. Tiền xử lý đặc trưng & nhãn
    target = "Malicecontent"
    ignore_cols = ["filename", target]
    features = [c for c in df.columns if c not in ignore_cols]

    X = df[features].copy()
    y = df[target].copy()

    # Xử lý missing values nếu có
    X = X.fillna(0)

    count_safe = (y == 0).sum()
    count_mal = (y == 1).sum()
    scale_weight = count_safe / count_mal if count_mal > 0 else 1.0

    print(f"[*] Số lượng đặc trưng PDF: {len(features)}")
    print(f"[*] Phân bố nhãn: PDF an toàn (0) = {count_safe}, PDF chứa mã độc/script (1) = {count_mal}")
    print(f"[*] Áp dụng kỹ thuật cân bằng trọng số (Class-weight balancing): tỉ lệ {scale_weight:.1f}x")

    # 3. Phân chia Train / Test (80% / 20%) với Stratified Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[*] Tập Train: {X_train.shape[0]} mẫu | Tập Test: {X_test.shape[0]} mẫu (Test Malicious = {(y_test == 1).sum()})")

    # 4. Định nghĩa các thuật toán tối ưu cho dữ liệu mất cân bằng
    models = {
        "Random Forest (Balanced)": RandomForestClassifier(
            n_estimators=150, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "XGBoost (Weighted)": xgb.XGBClassifier(
            n_estimators=150, max_depth=6, scale_pos_weight=scale_weight,
            learning_rate=0.08, random_state=42, eval_metric="logloss"
        ),
        "LightGBM (Balanced)": lgb.LGBMClassifier(
            n_estimators=150, max_depth=6, class_weight="balanced",
            learning_rate=0.08, random_state=42, verbose=-1
        )
    }

    results = {}
    best_f1 = 0
    best_model_name = None
    best_model = None

    print("\n" + "-" * 60)
    print(f"{'Mô hình':<25} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'AUC':<10}")
    print("-" * 60)

    for name, clf in models.items():
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

        print(f"{name:<25} | {acc:<10.4f} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f} | {auc:<10.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = clf

    print("-" * 60)
    print(f"🏆 Mô hình xuất sắc nhất: {best_model_name} với F1-Score = {best_f1:.4f}")

    # 5. Lưu mô hình tốt nhất và danh sách đặc trưng
    os.makedirs("models", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    model_save_path = os.path.join("models", "pdf_detector_model.pkl")
    features_save_path = os.path.join("models", "pdf_features.json")

    joblib.dump(best_model, model_save_path)
    with open(features_save_path, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=4)

    print(f"[✓] Đã lưu mô hình PDF tại: {model_save_path}")
    print(f"[✓] Đã lưu danh sách đặc trưng PDF tại: {features_save_path}")

    # 6. Tạo biểu đồ trực quan hóa phục vụ Báo cáo môn học
    y_best_pred = best_model.predict(X_test)
    cm = confusion_matrix(y_test, y_best_pred)

    # 6.1 Ma trận nhầm lẫn
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Greens",
                xticklabels=["PDF Sạch (0)", "PDF Độc/Script (1)"],
                yticklabels=["PDF Sạch (0)", "PDF Độc/Script (1)"])
    plt.title(f"Ma trận nhầm lẫn - Nhận diện PDF Độc hại\n({best_model_name})")
    plt.ylabel("Thực tế")
    plt.xlabel("Dự đoán")
    plt.tight_layout()
    cm_path = os.path.join("reports", "pdf_confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[✓] Đã lưu biểu đồ Ma trận nhầm lẫn tại: {cm_path}")

    # 6.2 Biểu đồ Top đặc trưng quan trọng
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        feat_df = pd.DataFrame({"Feature": features, "Importance": importances})
        feat_df = feat_df.sort_values(by="Importance", ascending=False).head(12)

        plt.figure(figsize=(10, 6))
        sns.barplot(data=feat_df, x="Importance", y="Feature", hue="Feature", palette="mako", legend=False)
        plt.title(f"Top 12 Đặc trưng PDF quan trọng nhất ({best_model_name})")
        plt.xlabel("Mức độ quan trọng (Feature Importance)")
        plt.ylabel("Đặc trưng thẻ cấu trúc PDF")
        plt.tight_layout()
        fi_path = os.path.join("reports", "pdf_feature_importance.png")
        plt.savefig(fi_path, dpi=300)
        plt.close()
        print(f"[✓] Đã lưu biểu đồ Top Đặc trưng tại: {fi_path}")

    # 6.3 Biểu đồ So sánh các Mô hình
    df_results = pd.DataFrame(results).T
    plt.figure(figsize=(10, 5))
    df_results[["Accuracy", "Precision", "Recall", "F1-Score"]].plot(kind="bar", figsize=(10, 5), colormap="crest")
    plt.title("So sánh Hiệu Năng Các Thuật Toán Nhận Diện PDF Độc Hại")
    plt.ylabel("Điểm số (0 - 1)")
    plt.ylim(0.85, 1.02)
    plt.xticks(rotation=0)
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.legend(loc="lower right")
    plt.tight_layout()
    comp_path = os.path.join("reports", "pdf_model_comparison.png")
    plt.savefig(comp_path, dpi=300)
    plt.close()
    print(f"[✓] Đã lưu biểu đồ So sánh mô hình tại: {comp_path}")

    # 6.4 File tóm tắt số liệu JSON
    summary_path = os.path.join("reports", "pdf_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump({
            "best_model": best_model_name,
            "metrics": results[best_model_name],
            "all_results": results,
            "total_samples": len(df),
            "feature_count": len(features)
        }, f, indent=4)

    print(f"[✓] Đã xuất báo cáo tổng kết JSON tại: {summary_path}")
    print("\n🎉 HUẤN LUYỆN PDF MODEL HOÀN TẤT!")

if __name__ == "__main__":
    train_pdf_pipeline()
