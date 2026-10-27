-- =====================================================================
-- Скрипт для создания учебной БД и расследования инцидентов ИБ (T-SQL)
-- =====================================================================

-- 1. Создание базы данных
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'SOC_Lab')
BEGIN
    CREATE DATABASE SOC_Lab;
END
GO

USE SOC_Lab;
GO

-- 2. Очистка старых таблиц (если существуют)
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS auth_logs;
GO

-- 3. Создание таблиц
CREATE TABLE auth_logs (
    id INT IDENTITY(1,1) PRIMARY KEY,
    ip_address VARCHAR(15),
    event_id INT,
    timestamp DATETIME
);

CREATE TABLE transactions (
    transaction_id INT PRIMARY KEY,
    user_name VARCHAR(50),
    amount INT,
    city VARCHAR(50),
    time DATETIME
);
GO

-- 4. Наполнение тестовыми данными (симуляция инцидентов)
-- 11 неудачных попыток входа с одного IP (Brute-force)
INSERT INTO auth_logs (ip_address, event_id, timestamp) 
SELECT '192.168.1.100', 4625, GETDATE() FROM (VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11)) AS T(n);

-- Транзакции: одна подозрительная (ночь, крупная сумма), две обычные
INSERT INTO transactions VALUES 
(101, 'Ivanov', 150000, 'Moscow', '2026-10-27T03:15:00'),
(102, 'Petrov', 5000, 'London', '2026-10-27T14:30:00'),
(103, 'Smirnov', 250000, 'Kazan', '2026-10-27T02:45:00');
GO

-- =====================================================================
-- 5. Аналитические запросы (Расследование)
-- =====================================================================

-- Запрос 1: Поиск брутфорса (IP с более чем 10 неудачными входами)
SELECT 
    ip_address, 
    COUNT(*) AS failed_attempts
FROM 
    auth_logs
WHERE 
    event_id = 4625 
GROUP BY 
    ip_address
HAVING 
    COUNT(*) > 10;

-- Запрос 2: Поиск подозрительных транзакций (Антифрод)
-- Выявляет крупные переводы (более 100 000), совершенные в ночное время
SELECT 
    transaction_id, 
    user_name, 
    amount, 
    city, 
    time
FROM 
    transactions
WHERE 
    amount > 100000 
    AND DATEPART(hour, time) >= 0 
    AND DATEPART(hour, time) < 6;
