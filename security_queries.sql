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

-- 2. Очистка старых объектов (в порядке зависимостей, чтобы не было ошибок FK)
DROP VIEW IF EXISTS vw_SecurityDashboard;
DROP TABLE IF EXISTS Transactions;
DROP TABLE IF EXISTS AuthLogs;
DROP TABLE IF EXISTS Assets;
DROP TABLE IF EXISTS Users;
GO

-- 3. Создание нормализованных таблиц со связями (Foreign Keys)
CREATE TABLE Users (
    UserID INT IDENTITY(1,1) PRIMARY KEY,
    Username VARCHAR(50) NOT NULL UNIQUE,
    Department VARCHAR(50),
    Role VARCHAR(50) DEFAULT 'Employee'
);

CREATE TABLE Assets (
    AssetID INT IDENTITY(1,1) PRIMARY KEY,
    Hostname VARCHAR(50) NOT NULL,
    IP_Address VARCHAR(15) NOT NULL UNIQUE,
    OS_Type VARCHAR(50)
);

CREATE TABLE AuthLogs (
    LogID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT FOREIGN KEY REFERENCES Users(UserID),
    AssetID INT FOREIGN KEY REFERENCES Assets(AssetID),
    EventID INT, -- 4625 = Failed Logon, 4624 = Successful Logon
    LogTime DATETIME DEFAULT GETDATE()
);

CREATE TABLE Transactions (
    TransactionID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT FOREIGN KEY REFERENCES Users(UserID),
    Amount DECIMAL(18,2),
    City VARCHAR(50),
    TransTime DATETIME
);
GO

-- =====================================================================
-- 4. НАПОЛНЕНИЕ ДАННЫМИ (Генерация 200+ записей)
-- =====================================================================

-- Пользователи (10 человек, включая админа)
INSERT INTO Users (Username, Department, Role) VALUES 
('ivanov', 'Finance', 'Employee'),
('smirnov', 'Finance', 'Manager'),
('petrov', 'IT', 'Admin'),
('sidorov', 'HR', 'Employee'),
('kuznetsov', 'Sales', 'Employee'),
('popov', 'IT', 'DevOps'),
('vasiliev', 'Marketing', 'Employee'),
('sokolov', 'Sales', 'Employee'),
('mikhailov', 'Finance', 'Employee'),
('admin', 'IT', 'Administrator'); -- Высокоприоритетная цель для хакеров

-- Устройства (10 активов)
INSERT INTO Assets (Hostname, IP_Address, OS_Type) VALUES 
('FIN-PC-01', '192.168.1.10', 'Windows 10'),
('FIN-PC-02', '192.168.1.11', 'Windows 10'),
('HR-PC-01', '192.168.1.12', 'macOS'),
('SALES-PC-01', '192.168.1.13', 'Windows 11'),
('IT-PC-01', '192.168.1.14', 'Ubuntu'),
('SRV-DB-01', '10.0.0.50', 'Windows Server'),
('SRV-WEB-01', '10.0.0.51', 'Ubuntu'),
('EXT-VPN-01', '8.8.8.8', 'Unknown'), -- Внешний IP (Хакер)
('EXT-VPN-02', '4.4.4.4', 'Unknown'), -- Внешний IP (Лондон)
('HOME-PC', '77.77.77.77', 'Windows 10');

-- А) Генерация 100 случайных логов (Обычный рабочий шум)
INSERT INTO AuthLogs (UserID, AssetID, EventID, LogTime)
SELECT TOP 100
    (ABS(CHECKSUM(NEWID())) % 9) + 1, 
    (ABS(CHECKSUM(NEWID())) % 7) + 1, 
    CASE WHEN ABS(CHECKSUM(NEWID())) % 5 = 0 THEN 4625 ELSE 4624 END, 
    DATEADD(minute, -ABS(CHECKSUM(NEWID())) % 10000, GETDATE()) 
FROM sys.all_objects a CROSS JOIN sys.all_objects b;

-- Б) ИНЦИДЕНТ 1: Брутфорс (25 неудачных попыток подбора пароля к УЧЕТКЕ ADMIN с IP '8.8.8.8')
INSERT INTO AuthLogs (UserID, AssetID, EventID, LogTime)
SELECT (SELECT UserID FROM Users WHERE Username = 'admin'), 
       (SELECT AssetID FROM Assets WHERE IP_Address = '8.8.8.8'),
       4625, DATEADD(second, n, '2026-10-27T03:00:00') 
FROM (SELECT TOP 25 ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n FROM sys.all_objects) AS T;

-- В) ИНЦИДЕНТ 2: Impossible Travel (Иванов в офисе в 10:00, и в Лондоне в 10:02)
INSERT INTO AuthLogs (UserID, AssetID, EventID, LogTime) VALUES 
((SELECT UserID FROM Users WHERE Username = 'ivanov'), (SELECT AssetID FROM Assets WHERE IP_Address = '192.168.1.10'), 4624, '2026-10-27T10:00:00'),
((SELECT UserID FROM Users WHERE Username = 'ivanov'), (SELECT AssetID FROM Assets WHERE IP_Address = '4.4.4.4'), 4624, '2026-10-27T10:02:00');

-- Г) Генерация 100 случайных транзакций (обычные покупки)
INSERT INTO Transactions (UserID, Amount, City, TransTime)
SELECT TOP 100
    (ABS(CHECKSUM(NEWID())) % 9) + 1, 
    (ABS(CHECKSUM(NEWID())) % 4900) + 100, 
    CASE (ABS(CHECKSUM(NEWID())) % 4) 
        WHEN 0 THEN 'Moscow'
        WHEN 1 THEN 'Kazan'
        WHEN 2 THEN 'SPb'
        ELSE 'Novosibirsk' END,
    DATEADD(minute, -ABS(CHECKSUM(NEWID())) % 15000, GETDATE())
FROM sys.all_objects a CROSS JOIN sys.all_objects b;

-- Д) ИНЦИДЕНТ 3: Антифрод (Аномально крупные транзакции)
INSERT INTO Transactions (UserID, Amount, City, TransTime) VALUES 
((SELECT UserID FROM Users WHERE Username = 'ivanov'), 150000.00, 'Moscow', '2026-10-27T03:15:00'),
((SELECT UserID FROM Users WHERE Username = 'smirnov'), 250000.00, 'Kazan', '2026-10-27T02:45:00'),
((SELECT UserID FROM Users WHERE Username = 'kuznetsov'), 95000.00, 'London', '2026-10-27T04:20:00');
GO

-- =====================================================================
-- 5. АНАЛИТИЧЕСКИЕ ЗАПРОСЫ (THREAT HUNTING)
-- =====================================================================

-- Запрос 1: Поиск брутфорса (JOIN, GROUP BY, HAVING)
-- Задача: найти IP-адреса, с которых было более 10 неудачных попыток входа.
SELECT 
    a.IP_Address,
    u.Username,
    COUNT(al.LogID) AS Failed_Attempts,
    MIN(al.LogTime) AS First_Attempt,
    MAX(al.LogTime) AS Last_Attempt
FROM AuthLogs al
JOIN Assets a ON al.AssetID = a.AssetID
JOIN Users u ON al.UserID = u.UserID
WHERE al.EventID = 4625
GROUP BY a.IP_Address, u.Username
HAVING COUNT(al.LogID) > 10;

-- Запрос 2: Антифрод (CTE + Оконная функция AVG)
-- Задача: найти транзакции, которые превышают средний чек пользователя в 5 раз.
WITH UserAvg AS (
    SELECT 
        UserID, 
        AVG(Amount) AS AvgAmount
    FROM Transactions
    GROUP BY UserID
)
SELECT 
    t.TransactionID,
    u.Username,
    t.Amount,
    ROUND(ua.AvgAmount, 2) AS AvgAmount,
    -- Оконная функция вычисляет отклонение от среднего в процентах
    ROUND((t.Amount / ua.AvgAmount) * 100, 2) AS PercentOfAvg,
    FORMAT(t.TransTime, 'yyyy-MM-dd HH:mm') AS TransTime
FROM Transactions t
JOIN UserAvg ua ON t.UserID = ua.UserID
JOIN Users u ON t.UserID = u.UserID
WHERE t.Amount > (ua.AvgAmount * 5) -- Сумма больше среднего в 5 раз
ORDER BY t.Amount DESC;

-- Запрос 3: Поиск "Невозможных путешествий" (Impossible Travel) через CTE и LAG
-- Задача: найти пользователей, которые зашли с разных IP в слишком короткий промежуток времени.
WITH LoginSequence AS (
    SELECT 
        UserID,
        AssetID,
        LogTime,
        -- Функция LAG смотрит на предыдущий вход этого же пользователя
        LAG(LogTime) OVER(PARTITION BY UserID ORDER BY LogTime) AS PrevLoginTime,
        LAG(AssetID) OVER(PARTITION BY UserID ORDER BY LogTime) AS PrevAssetID
    FROM AuthLogs
    WHERE EventID = 4624 -- Только успешные входы
)
SELECT 
    u.Username,
    a1.IP_Address AS Current_IP,
    a2.IP_Address AS Previous_IP,
    ls.PrevLoginTime AS Previous_Login,
    ls.LogTime AS Current_Login,
    DATEDIFF(MINUTE, ls.PrevLoginTime, ls.LogTime) AS MinutesBetween
FROM LoginSequence ls
JOIN Users u ON ls.UserID = u.UserID
JOIN Assets a1 ON ls.AssetID = a1.AssetID
JOIN Assets a2 ON ls.PrevAssetID = a2.AssetID
WHERE 
    -- Если входы были с разных устройств и разница менее 15 минут
    ls.AssetID != ls.PrevAssetID 
    AND DATEDIFF(MINUTE, ls.PrevLoginTime, ls.LogTime) < 15;
GO

-- =====================================================================
-- 6. СОЗДАНИЕ ПРЕДСТАВЛЕНИЯ (VIEW) ДЛЯ ДАШБОРДА SOC
-- =====================================================================
-- Это удобно для аналитиков L1: они просто открывают View и видят сводку событий.
CREATE OR ALTER VIEW vw_SecurityDashboard AS
SELECT 
    al.LogTime,
    u.Username,
    a.IP_Address,
    CASE 
        WHEN al.EventID = 4625 THEN 'FAILED LOGIN'
        WHEN al.EventID = 4624 THEN 'SUCCESS LOGIN'
        ELSE 'OTHER'
    END AS EventType
FROM AuthLogs al
JOIN Users u ON al.UserID = u.UserID
JOIN Assets a ON al.AssetID = a.AssetID;
GO

-- Проверка работы View (выводит красивую сводку последних событий):
SELECT TOP 20 * FROM vw_SecurityDashboard ORDER BY LogTime DESC;
