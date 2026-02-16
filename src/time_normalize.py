import pandas as pd
import numpy as np

def parse_time_with_timezone(time_str):
    """Парсинг времени с часовым поясом MDT"""
    if pd.isna(time_str) or not isinstance(time_str, str):
        return pd.NaT
    
    # Удаляем часовой пояс из строки
    if ' MDT' in time_str:
        time_str = time_str.replace(' MDT', '')
    elif ' MST' in time_str:
        time_str = time_str.replace(' MST', '')
    
    return time_str

def normalize_security_time(df):
    """Обрабатывает временные поля в security_logs DataFrame"""
    if '_time' in df.columns:
        # Сначала удаляем часовой пояс из строки
        df['_time_clean'] = df['_time'].apply(parse_time_with_timezone)
        
        # Преобразуем в datetime без часового пояса
        df['timestamp'] = pd.to_datetime(df['_time_clean'], errors='coerce')
        
        # Добавляем правильный часовой пояс (MDT = America/Denver)
        df['timestamp'] = df['timestamp'].dt.tz_localize('America/Denver')
       
        # Конвертируем в UTC для единообразия
        df['timestamp_utc'] = df['timestamp'].dt.tz_convert('UTC')
       
        # Конвертируем в московское время
        df['timestamp_moscow'] = df['timestamp'].dt.tz_convert('Europe/Moscow')
        
        # Извлекаем компоненты даты/времени (используем UTC для единообразия)
        df['year'] = df['timestamp_utc'].dt.year
        df['month'] = df['timestamp_utc'].dt.month
        df['day'] = df['timestamp_utc'].dt.day
        df['hour'] = df['timestamp_utc'].dt.hour
        df['minute'] = df['timestamp_utc'].dt.minute
        df['second'] = df['timestamp_utc'].dt.second
        df['day_of_week'] = df['timestamp_utc'].dt.day_name()
        
        print("   Приведено к единому формату времени")
        return df
    
    else:
        print("   Поле _time не найдено")
        # Альтернативный вариант: используем компоненты даты из данных
        if all(field in df.columns for field in ['date_year', 'date_month', 'date_mday', 'date_hour', 'date_minute', 'date_second']):
            # Создаем строку времени из компонентов
            df['time_str'] = (
                df['date_year'].astype(str) + '-' + 
                df['date_month'].astype(str).str.zfill(2) + '-' + 
                df['date_mday'].astype(str).str.zfill(2) + ' ' + 
                df['date_hour'].astype(str).str.zfill(2) + ':' + 
                df['date_minute'].astype(str).str.zfill(2) + ':' + 
                df['date_second'].astype(str).str.zfill(2)
            )
            df['timestamp'] = pd.to_datetime(df['time_str'], errors='coerce')
            df['timestamp'] = df['timestamp'].dt.tz_localize('America/Denver')
            df['timestamp_utc'] = df['timestamp'].dt.tz_convert('UTC')
            print("   Время создано из компонентов даты")
            return df
        
        return df
