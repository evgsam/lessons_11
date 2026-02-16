import pandas as pd
import os
import json


current_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_dir, "botsv1.json")

# Читаем JSON файл
with open(file_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Извлекаем данные из поля 'result' для каждой записи
records = [item['result'] for item in data]

# Создаем DataFrame
security_logs = pd.DataFrame(records)
print("   Данные загружены в DataFrame")

def parse_time_with_timezone(time_str):
    """парсинг времени с часовым поясом MDT"""
    if pd.isna(time_str) or not isinstance(time_str, str):
        return pd.NaT
    
    # Удаляем часовой пояс из строки
    if ' MDT' in time_str:
        time_str = time_str.replace(' MDT', '')
    elif ' MST' in time_str:
        time_str = time_str.replace(' MST', '')
    
    return time_str

if '_time' in security_logs.columns:
    # Сначала удаляем часовой пояс из строки
    security_logs['_time_clean'] = security_logs['_time'].apply(parse_time_with_timezone)
    
    # Преобразуем в datetime без часового пояса
    security_logs['timestamp'] = pd.to_datetime(security_logs['_time_clean'], errors='coerce')
    
    # Добавляем правильный часовой пояс (MDT = America/Denver)
    # Mountain Time Zone обычно America/Denver
    security_logs['timestamp'] = security_logs['timestamp'].dt.tz_localize('America/Denver')
   
    # Конвертируем в UTC для единообразия
    security_logs['timestamp_utc'] = security_logs['timestamp'].dt.tz_convert('UTC')
   
    # Конвертируем в московское время
    security_logs['timestamp_moscow'] = security_logs['timestamp'].dt.tz_convert('Europe/Moscow')
    
    # Извлекаем компоненты даты/времени (используем UTC для единообразия)
    security_logs['year'] = security_logs['timestamp_utc'].dt.year
    security_logs['month'] = security_logs['timestamp_utc'].dt.month
    security_logs['day'] = security_logs['timestamp_utc'].dt.day
    security_logs['hour'] = security_logs['timestamp_utc'].dt.hour
    security_logs['minute'] = security_logs['timestamp_utc'].dt.minute
    security_logs['second'] = security_logs['timestamp_utc'].dt.second
    security_logs['day_of_week'] = security_logs['timestamp_utc'].dt.day_name()
    
    print("   Приведено к единому формату времени")
else:
    print("   Поле _time не найдено")
    # Альтернативный вариант: используем компоненты даты из данных
    if all(field in security_logs.columns for field in ['date_year', 'date_month', 'date_mday', 'date_hour', 'date_minute', 'date_second']):
        # Создаем строку времени из компонентов
        security_logs['time_str'] = (
            security_logs['date_year'] + '-' + 
            security_logs['date_month'] + '-' + 
            security_logs['date_mday'] + ' ' + 
            security_logs['date_hour'] + ':' + 
            security_logs['date_minute'] + ':' + 
            security_logs['date_second']
        )
        security_logs['timestamp'] = pd.to_datetime(security_logs['time_str'], errors='coerce')
        security_logs['timestamp'] = security_logs['timestamp'].dt.tz_localize('America/Denver')
        security_logs['timestamp_utc'] = security_logs['timestamp'].dt.tz_convert('UTC')
        print("   Время создано из компонентов даты")

# 2. Очистка от пропусков
# Проверка пропусков
missing_counts = security_logs.isnull().sum()
missing_percent = (missing_counts / len(security_logs)) * 100
missing_df = pd.DataFrame({
    'Пропусков': missing_counts,
    'Процент': missing_percent
}).sort_values('Пропусков', ascending=False)

# Заполняем пропуски в текстовых полях
text_columns = security_logs.select_dtypes(include=['object']).columns
for col in text_columns:
    security_logs[col] = security_logs[col].fillna('Unknown')

# Заполняем пропуски в числовых полях
numeric_columns = security_logs.select_dtypes(include=['int64', 'float64']).columns
for col in numeric_columns:
    security_logs[col] = security_logs[col].fillna(0)

print("   Пропуски очищены")

#3 Удаление дубликатов
initial_count = len(security_logs)

# Используем ключевые колонки для определения уникальности
key_columns = ['_time', 'EventCode', 'RecordNumber']
available_key_columns = [col for col in key_columns if col in security_logs.columns]

if available_key_columns:
    security_logs = security_logs.drop_duplicates(subset=available_key_columns)
else:
    security_logs = security_logs.drop_duplicates()

print("   Дубликаты удалены")

event_id_fields = ['EventCode', 'signature_id']
for field in event_id_fields:
    if field in security_logs.columns:
        security_logs[field] = pd.to_numeric(security_logs[field], errors='coerce')
        security_logs[field] = security_logs[field].fillna(0).astype(int)

print("   Типы данных преобразованы")

#security_logs.to_csv('normalized_botsv1.csv', index=False, encoding='utf-8')
#print("\nНормализованные данные сохранены в файл 'normalized_botsv1.csv'")

# Список подозрительных EventID
suspicious_events = {
    4624: "Успешный вход в систему",
    4625: "Неудачная попытка входа",
    4634: "Выход из системы",
    4647: "Инициация выхода из системы",
    4672: "Особые привилегии",
    4688: "Создание процесса",
    4689: "Завершение процесса",
    4703: "Изменение прав пользователя",
    4720: "Создание пользователя",
    4732: "Добавление в группу",
    4740: "Блокировка учетной записи"
}

# Проверяем наличие поля с EventID
event_id_field = None
for field in ['EventCode', 'signature_id']:
    if field in security_logs.columns:
        event_id_field = field
        break

if event_id_field:
    # Создаем копию для анализа
    analysis_df = security_logs.copy()
    
    # Добавляем описание подозрительных событий
    analysis_df['suspicious_desc'] = analysis_df[event_id_field].map(suspicious_events)
    
    # Фильтруем подозрительные события
    suspicious_df = analysis_df[analysis_df['suspicious_desc'].notna()].copy()
    
    print(f"\nНайдено подозрительных событий: {len(suspicious_df)}")
    
    if len(suspicious_df) > 0:
        # Группируем по EventID
        event_counts = suspicious_df.groupby([event_id_field, 'suspicious_desc']).size().reset_index(name='count')
        event_counts = event_counts.sort_values('count', ascending=False)
        
        print("\nТоп подозрительных событий:")
        print(event_counts.to_string(index=False))
        
        # Визуализация
        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            plt.figure(figsize=(12, 6))
            
            # Берем топ-10
            top_10 = event_counts.head(10)
            
            # Создаем горизонтальный барплот для лучшей читаемости
            plt.figure(figsize=(10, 6))
            bars = plt.barh(range(len(top_10)), top_10['count'].values)
            plt.yticks(range(len(top_10)), [f"Event {row[event_id_field]}\n{row['suspicious_desc']}" 
                                           for _, row in top_10.iterrows()])
            plt.xlabel('Количество событий')
            plt.title('Топ-10 подозрительных событий')
            
            # Добавляем значения на столбцы
            for i, (_, row) in enumerate(top_10.iterrows()):
                plt.text(row['count'], i, f' {row["count"]}', va='center')
            
            plt.tight_layout()
            plt.savefig('suspicious_events.png', dpi=300, bbox_inches='tight')
            plt.show()
            print("\nГрафик сохранен в файл 'suspicious_events.png'")
            
        except ImportError:
            print("\nДля визуализации установите matplotlib и seaborn:")
            print("pip install matplotlib seaborn")
    else:
        print("   Подозрительных событий не найдено")
else:
    print("   Не найдено поле с EventID для анализа")