import os
import pandas as pd
import json
from datetime import datetime
from time_normalize import normalize_security_time
from data_normalize import normalize_data
from event_id_check import check_suspicious_events

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "botsv1.json")
    
    # Читаем как единый JSON-массив
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)  # data — это list of dicts

    # Извлекаем данные из поля 'result' для каждой записи
    records = [item['result'] for item in data]

    # Создаем DataFrame
    security_logs = pd.DataFrame(records)
    print("   Данные загружены в DataFrame")

    #нормализую по времени
    security_logs = normalize_security_time(security_logs)
    #нормализую данные
    security_logs = normalize_data(security_logs)
    #анализ eventId
    check_suspicious_events(security_logs)
if __name__ == "__main__":
    main()
