import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

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

def check_suspicious_events(df):
    """
    Анализ подозрительных событий по EventID
    """
    # Проверяем наличие поля с EventID
    event_id_field = None
    for field in ['EventCode', 'signature_id']:
        if field in df.columns:
            event_id_field = field
            break

    if event_id_field:
        # Создаем копию для анализа
        analysis_df = df.copy()
        
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
    
    return df  # Возвращаем DataFrame для цепочки
