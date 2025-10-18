import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# Chemins
dataset_path = r"D:\dataset\combine.csv"
save_dir = r"C:\Users\pc\OneDrive - ISGA\Bureau\projet2K26"

# Lecture du dataset avec nettoyage des noms de colonnes
df = pd.read_csv(dataset_path, low_memory=False)
df.columns = df.columns.str.strip()  # Nettoyage noms colonnes

print("Colonnes du dataset :", df.columns.tolist())

# Recherche colonne label
possible_label_cols = ['label', 'class', 'attack', 'target']
label_col = None
for col in df.columns:
    if col.lower() in possible_label_cols:
        label_col = col
        break

if label_col is None:
    raise Exception("❌ Aucune colonne de label valide trouvée dans le dataset.")

print(f"Colonne label utilisée : '{label_col}'")

# Séparer features et labels
X = df.drop(columns=[label_col])
y = df[label_col]

# Encoder label binaire si nécessaire
if y.dtype == object:
    y = y.apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)

# Forcer conversion en numérique, erreurs deviennent NaN
X = X.apply(pd.to_numeric, errors='coerce')
# Remplacer NaN par 0
X = X.fillna(0)
# Remplacer les valeurs infinies par des valeurs finies
X = X.replace([float('inf'), -float('inf')], [1e30, -1e30])

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Entraîner modèle
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Évaluer
y_pred = clf.predict(X_test)
print("\n--- Rapport de classification ---")
print(classification_report(y_test, y_pred))

# Sauvegarder modèle
os.makedirs(save_dir, exist_ok=True)
model_path = os.path.join(save_dir, 'model_rf.pkl')
joblib.dump(clf, model_path)
print(f"✅ Modèle sauvegardé ici : {model_path}")
