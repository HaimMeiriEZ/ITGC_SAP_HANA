import pandas as pd
import json
import os
from typing import Dict, Optional

class DataImporter:
    """
    אחראי על טעינת קבצי CSV שהופקו מ-SAP HANA וניקוי ראשוני שלהם.
    משתמש ב-Pandas ליעילות מקסימלית.
    """
    
    def __init__(self, config_path: str = "config/settings.json"):
        self.config = self._load_config(config_path)

    def _load_config(self, path: str) -> Dict:
        if not os.path.exists(path):
            # ברירת מחדל בסיסית אם הקובץ חסר
            return {"critical_users": [], "critical_privileges": []}
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def load_hana_csv(self, file_path: str) -> Optional[pd.DataFrame]:
        """
        טוען קובץ CSV, מנקה שמות עמודות וערכים (הסרת גרשיים ורווחים).
        """
        try:
            # SAP HANA לעיתים מייצא עם קידוד UTF-16 או עם גרשיים כפולים
            df = pd.read_csv(file_path, sep=None, engine='python', quotechar='"', skipinitialspace=True)
            
            # בחלק מייצואי HANA יש עמודת אינדקס ריקה ראשונה שיש להסיר.
            first_column = str(df.columns[0]).strip().upper()
            if first_column == "" or first_column.startswith("UNNAMED"):
                df = df.iloc[:, 1:]
            
            # ניקוי שמות עמודות - הפיכה לאותיות גדולות והסרת רווחים
            df.columns = [str(col).strip().upper().replace('"', '') for col in df.columns]
            
            # ניקוי תוכן התאים - הסרת רווחים מיותרים
            if hasattr(df, "map"):
                df = df.map(lambda x: x.strip().replace('"', '') if isinstance(x, str) else x)
            else:
                df = df.applymap(lambda x: x.strip().replace('"', '') if isinstance(x, str) else x)
            
            print(f"[Success] Loaded {len(df)} rows from {file_path}")
            return df
            
        except Exception as e:
            print(f"[Error] Failed to load {file_path}: {e}")
            return None

    def identify_and_load(self, directory_path: str) -> Dict[str, pd.DataFrame]:
        """
        סורק תיקייה ומנסה לזהות קבצים לפי המיפוי בהגדרות.
        """
        loaded_data = {}
        mappings = self.config.get("file_mappings", {})
        
        for file_type, filename in mappings.items():
            full_path = os.path.join(directory_path, filename)
            if os.path.exists(full_path):
                df = self.load_hana_csv(full_path)
                if df is not None:
                    loaded_data[file_type] = df
            else:
                print(f"[Warning] Expected file {filename} for {file_type} not found.")
                
        return loaded_data

# דוגמת שימוש מהירה (תגובה לבדיקה)
if __name__ == "__main__":
    importer = DataImporter()
    # כאן נריץ את הבדיקה כשיהיו קבצים