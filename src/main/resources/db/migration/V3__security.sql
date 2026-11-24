-- Лаба 4. Учётные записи для Spring Security.
-- Логин — email, пароль хранится только в виде BCrypt-хеша.

ALTER TABLE users
    ADD COLUMN password_hash         VARCHAR(100),
    ADD COLUMN role                  VARCHAR(20) NOT NULL DEFAULT 'TRANSLATOR'
        CHECK (role IN ('ADMIN', 'EDITOR', 'TRANSLATOR')),
    -- ACTIVE — может входить, BLOCKED — заблокирован администратором
    ADD COLUMN status                VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'BLOCKED')),
    -- защита от подбора пароля: счётчик неудачных входов и время окончания временной блокировки
    ADD COLUMN failed_login_attempts INTEGER     NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    ADD COLUMN locked_until          TIMESTAMPTZ;

-- Тестовые пользователи из V2 получают пароли и роли.
--   anna.editor@demo.local       — EDITOR,     пароль Editor#2024
--   boris.translator@demo.local  — TRANSLATOR, пароль Translator#2024
--   vera.translator@demo.local   — TRANSLATOR, пароль Translator#2024
UPDATE users SET role = 'EDITOR',
                 password_hash = '$2a$10$W6dKQP0P17QzHOOrIMSGNOCVr7lEp6MWovyyVl7kiR8FshiGU/aum'
WHERE email = 'anna.editor@demo.local';

UPDATE users SET role = 'TRANSLATOR',
                 password_hash = '$2a$10$AAM4mSAeoc1V8WtxdKRBWuFEWWmidtUjhrZgrOAG6PkyZatxcFXlO'
WHERE email IN ('boris.translator@demo.local', 'vera.translator@demo.local');

-- Пользователи, созданные через API в лабе 3, пароля не имеют. Войти они не смогут:
-- '!' не является BCrypt-хешом, а сама запись заблокирована до решения администратора.
UPDATE users SET password_hash = '!', status = 'BLOCKED'
WHERE password_hash IS NULL;

ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

-- Администратор. Зарегистрироваться администратором через API нельзя, поэтому он создаётся миграцией.
--   admin@demo.local — ADMIN, пароль Admin#2024
INSERT INTO users (name, email, password_hash, role, status, created_at, updated_at)
VALUES ('Администратор', 'admin@demo.local',
        '$2a$10$ENaGqoMGhyu/bpaelKQiXuOskyByKxu154Xur4M3Sh4QJ3s5JPJLi', 'ADMIN', 'ACTIVE', now(), now());
