import pandas as pd
import numpy as np

def normalize_data(df):
    """ нормализация: пропуски + дубликаты + типы данных"""
    # Проверка пропусков
    missing_counts = df.isnull().sum()
    missing_percent = (missing_counts / len(df)) * 100
    missing_df = pd.DataFrame({
        'Пропусков': missing_counts,
        'Процент': missing_percent
    }).sort_values('Пропусков', ascending=False)

    # Заполняем пропуски в текстовых полях
    text_columns = df.select_dtypes(include=['object']).columns
    for col in text_columns:
        df[col] = df[col].fillna('Unknown')

# Заполняем пропуски в числовых полях
    numeric_columns = df.select_dtypes(include=['int64', 'float64']).columns
    for col in numeric_columns:
        df[col] = df[col].fillna(0)

    print("   Пропуски очищены")
    
    # 3. Удаление дубликатов
    key_columns = ['_time', 'EventCode', 'RecordNumber']
    available_key_columns = [col for col in key_columns if col in df.columns]
    
    if available_key_columns:
        df = df.drop_duplicates(subset=available_key_columns, ignore_index=True)
    else:
        df = df.drop_duplicates(ignore_index=True)
    
    print("   Дубликаты удалены")
    
    # 4. Нормализация Event ID полей
    event_id_fields = ['EventCode', 'signature_id']
    for field in event_id_fields:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors='coerce').fillna(0).astype(int)


    event_id_fields = ['EventCode', 'signature_id']
    for field in event_id_fields:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors='coerce')
            df[field] = df[field].fillna(0).astype(int)
    
    print("   Типы данных преобразованы")
    
    return df

